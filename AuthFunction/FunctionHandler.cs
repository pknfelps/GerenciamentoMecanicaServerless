using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Amazon.Lambda.Serialization.SystemTextJson;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Function.Http;
using GerenciamentoMecanica.Autenticacao.Function.Observability;
using System.Diagnostics;
using System.Text.Json;

namespace GerenciamentoMecanica.Autenticacao.Function;

public sealed class FunctionHandler : IDisposable, IAsyncDisposable
{
    private readonly FunctionRuntimeProvider? runtime;
    private readonly LambdaObservability? observability;
    private readonly Func<string?, CancellationToken, Task<CustomerCodeRequestResponse>> requestCode;
    private readonly Func<Guid, string?, string?, CancellationToken, Task<CustomerAuthenticationResult>> verifyCode;
    private readonly Func<string, string, string, CancellationToken, Task<string?>> internalLogin;

    public FunctionHandler() : this(LambdaObservability.CreateDefault())
    {
    }

    private FunctionHandler(LambdaObservability? observability) : this(
        new FunctionRuntimeProvider(new FunctionBootstrap(observability?.Integrations, observability?.CreateLogger<Infrastructure.Persistence.PostgreSqlCustomerAccessStore>()).InitializeAsync), observability)
    {
    }

    public FunctionHandler(FunctionRuntimeProvider runtime, LambdaObservability? observability = null)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        this.runtime = runtime;
        this.observability = observability;
        requestCode = runtime.RequestCodeAsync;
        verifyCode = runtime.VerifyCodeAsync;
        internalLogin = runtime.InternalLoginAsync;
    }

    public FunctionHandler(Func<string?, CancellationToken, Task<CustomerCodeRequestResponse>> requestCode,
        Func<Guid, string?, string?, CancellationToken, Task<CustomerAuthenticationResult>> verifyCode,
        LambdaObservability? observability = null,
        Func<string, string, string, CancellationToken, Task<string?>>? internalLogin = null)
    {
        ArgumentNullException.ThrowIfNull(requestCode);
        ArgumentNullException.ThrowIfNull(verifyCode);
        this.requestCode = requestCode;
        this.verifyCode = verifyCode;
        this.internalLogin = internalLogin ?? ((_, _, _, _) => throw new InvalidOperationException("Internal login is not configured."));
        this.observability = observability;
    }

    [LambdaSerializer(typeof(DefaultLambdaJsonSerializer))]
    public Task<APIGatewayProxyResponse> HandleAsync(APIGatewayProxyRequest request, ILambdaContext context) =>
        observability is null ? HandleCoreAsync(request, context) : observability.InvokeAsync(request, context, HandleCoreAsync);

    private async Task<APIGatewayProxyResponse> HandleCoreAsync(APIGatewayProxyRequest request, ILambdaContext context)
    {
        var elapsed = Stopwatch.StartNew();

        APIGatewayProxyResponse response;

        var category = "invalid-request";

        var route = AuthenticationRoute.Resolve(request);
        if (route == AuthenticationRoute.Unknown)
            response = AuthenticationResponse.NotFound();
        else if (request.HttpMethod != "POST")
            response = AuthenticationResponse.MethodNotAllowed(route);
        else if (route == AuthenticationRoute.InternalLogin)
        {
            var traceId = Activity.Current?.Id ?? request.RequestContext?.RequestId ?? context.AwsRequestId ?? string.Empty;
            var invalid = InternalLoginRequestParser.Parse(request, traceId, out var loginInput);
            if (invalid is not null)
                response = invalid;
            else
                (response, category) = await ExecuteWithDeadlineAsync(
                    token => ExecuteInternalLoginAsync(request, loginInput!, token), route, context);
        }
        else if (!CustomerCodeRequestParser.TryParse(request, route, out var input, out var invalidDocument))
        {
            response = AuthenticationResponse.InvalidRequest(route);
            if (invalidDocument) category = "invalid-document";
        }
        else
        {
            (response, category) = await ExecuteWithDeadlineAsync(token => ExecuteAsync(input!, route, token), route, context);
        }

        if (observability is not null)
            observability.Complete(context, request, response.StatusCode, category, elapsed.Elapsed);
        else
        {
            context.Logger.LogLine(JsonSerializer.Serialize(new
            {
                lambdaRequestId = context.AwsRequestId,
                gatewayRequestId = request.RequestContext?.RequestId,
                status = response.StatusCode,
                durationMs = elapsed.ElapsedMilliseconds,
                category
            }));
        }

        return response;
    }

    private async Task<(APIGatewayProxyResponse Response, string Category)> ExecuteWithDeadlineAsync(
        Func<CancellationToken, Task<(APIGatewayProxyResponse Response, string Category)>> execute,
        string route, ILambdaContext context)
    {
        var budget = context.RemainingTime - TimeSpan.FromSeconds(1);
        using var cancellation = new CancellationTokenSource();
        try
        {
            if (budget <= TimeSpan.Zero) throw new OperationCanceledException();
            cancellation.CancelAfter(budget);
            var result = await execute(cancellation.Token).WaitAsync(cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            return result;
        }
        catch (Exception error)
        {
            observability?.RecordException(error);
            var response = route == AuthenticationRoute.InternalLogin
                ? InternalLoginResponse.TechnicalFailure()
                : AuthenticationResponse.TechnicalFailure(route);
            var category = error is OperationCanceledException or TimeoutException || cancellation.IsCancellationRequested
                ? "timeout" : "technical-failure";
            return (response, category);
        }
    }

    private async Task<(APIGatewayProxyResponse Response, string Category)> ExecuteInternalLoginAsync(
        APIGatewayProxyRequest request, InternalLoginInput input, CancellationToken cancellationToken)
    {
        var token = await internalLogin(input.Name!, input.Password!, input.Role!, cancellationToken);
        var response = InternalLoginResponse.FromToken(request, token);
        return (response, response.StatusCode == 200 ? "authenticated" : "invalid-credentials");
    }

    private async Task<(APIGatewayProxyResponse Response, string Category)> ExecuteAsync(CustomerCodeInput input, string route, CancellationToken cancellationToken)
    {
        if (route == AuthenticationRoute.RequestCode)
        {
            var result = await requestCode(input.Document, cancellationToken);
            var category = result.InvalidDocument ? "invalid-document" : result.RetryAfterSeconds > 0 ? "rate-limited" : "code-requested";
            return (AuthenticationResponse.FromRequest(result), category);
        }
        var verified = await verifyCode(input.ChallengeId, input.Document, input.Code, cancellationToken);
        var outcome = verified.Outcome switch
        {
            CustomerAuthenticationOutcome.Authenticated => "authenticated",
            CustomerAuthenticationOutcome.NotEligible => "not-eligible",
            _ => "invalid-document"
        };
        return (AuthenticationResponse.FromResult(verified), outcome);
    }

    public void Dispose()
    {
        try { runtime?.Dispose(); }
        finally { observability?.Dispose(); }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (runtime is not null)
                await runtime.DisposeAsync();
        }
        finally { observability?.Dispose(); }
    }
}
