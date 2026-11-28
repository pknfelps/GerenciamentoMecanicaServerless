using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Function;
using GerenciamentoMecanica.Autenticacao.Function.Http;
using GerenciamentoMecanica.Autenticacao.Function.Observability;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NSubstitute;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.Json;

namespace GerenciamentoMecanica.Autenticacao.FunctionTests.Observability;

[NonParallelizable]
public sealed class InvocationTelemetryTests
{
    private const string TraceId = "00000000000000000000000000000002";
    private const string ParentSpanId = "0000000000000202";
    private const string Password = "private-test-password";
    private const string IncomingToken = "private-incoming.jwt.token";
    private const string IssuedToken = "private-issued.jwt.token";
    private const string Code = "92514307";
    private const string Document = "52998224725";
    private const string Failure = "private database/configuration details and password hash";
    private const string Unknown = "/private-path";
    private const string UnknownMethod = "private-method";

    [TestCase("/authentication/", "POST", false, 200, "authenticated")]
    [TestCase("/authentication/", "POST", true, 500, "technical-failure")]
    [TestCase("/Users", "GET", false, 401, "unauthenticated")]
    [TestCase("/Users", "POST", false, 401, "unauthenticated")]
    [TestCase("/Users", "PATCH", false, 401, "unauthenticated")]
    [TestCase("/Users", "DELETE", false, 401, "unauthenticated")]
    [TestCase("/Users", "PATCH", true, 500, "technical-failure")]
    [TestCase("/customers/auth/verify-code", "POST", false, 200, "authenticated")]
    [TestCase("/private-path", "private-method", false, 404, "route-not-found")]
    public async Task SignalsUseKnownOperationsAndOmitSensitiveValues(
        string rawRoute, string rawMethod, bool fails, int status, string outcome)
    {
        var route = rawRoute switch
        {
            "/authentication/" => AuthenticationRoute.InternalLogin,
            Unknown => AuthenticationRoute.Unknown,
            _ => rawRoute
        };
        var method = rawMethod == UnknownMethod ? "OTHER" : rawMethod;
        var spans = new List<Activity>();
        var exportedLogs = new List<string>();
        var measurements = new List<(string Name, Dictionary<string, object?> Tags)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == InvocationMetrics.MeterName)
                    meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
            measurements.Add((instrument.Name, tags.ToArray().ToDictionary())));
        listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) =>
            measurements.Add((instrument.Name, tags.ToArray().ToDictionary())));
        listener.Start();

        using var configuration = Configuration();
        var originalPropagator = OpenTelemetry.Context.Propagation.Propagators.DefaultTextMapPropagator;
        try
        {
            var traceExporter = new TestExporter<Activity>(spans.Add);
            var logExporter = new TestExporter<LogRecord>(record => exportedLogs.Add(record.FormattedMessage ?? string.Empty));
            var telemetry = LambdaObservability.Create(configuration,
                configureTraces: builder => builder.AddProcessor(new SimpleActivityExportProcessor(traceExporter)),
                configureLogs: options => options.AddProcessor(new SimpleLogRecordExportProcessor(logExporter)));
            Assert.That(telemetry, Is.Not.Null);
            using var function = route == AuthenticationRoute.InternalUsers
                ? new FunctionHandler(new FunctionRuntimeProvider(_ => Task.FromException<FunctionRuntime>(new InvalidOperationException(Failure))), telemetry)
                : new FunctionHandler(
                    (_, _) => throw new AssertionException("Unexpected code request."),
                    (_, _, _, _) => Task.FromResult(CustomerAuthenticationResult.Authenticated(IssuedToken)),
                    telemetry, (_, _, _, _) => fails ? Task.FromException<string?>(new NpgsqlException(Failure)) : Task.FromResult<string?>(IssuedToken));

            var logger = Substitute.For<ILambdaLogger>();
            var context = Substitute.For<ILambdaContext>();
            context.Logger.Returns(logger);
            context.RemainingTime.Returns(TimeSpan.FromSeconds(5));
            context.InvokedFunctionArn.Returns("arn:aws:lambda:us-east-1:123456789012:function:auth-fixture");
            context.AwsRequestId.Returns("lambda-fixture-request");
            var request = new APIGatewayProxyRequest
            {
                Path = rawRoute,
                HttpMethod = rawMethod,
                RequestContext = new() { RequestId = "gateway-fixture-request" },
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json", ["traceparent"] = $"00-{TraceId}-{ParentSpanId}-01",
                    ["tracestate"] = "fixture=private-trace-state", ["baggage"] = "fixture=private-baggage",
                    ["Authorization"] = fails ? $"Bearer {IncomingToken}" : IncomingToken
                },
                Body = route == AuthenticationRoute.VerifyCode
                    ? JsonSerializer.Serialize(new { document = Document, challengeId = Guid.NewGuid(), code = Code })
                    : JsonSerializer.Serialize(new { name = "Conta fixture", password = Password, role = "Admin" })
            };

            var response = await function.HandleAsync(request, context);

            var line = logger.ReceivedCalls().Select(call => (string)call.GetArguments()[0]!)
                .Single(message => message.Contains("gateway-fixture-request", StringComparison.Ordinal));
            using var completion = JsonDocument.Parse(line);
            var log = completion.RootElement;
            var span = spans.Single();
            var serializedSignals = line + string.Join("", exportedLogs) + JsonSerializer.Serialize(new
            {
                span.DisplayName, span.StatusDescription, span.TraceStateString, span.Baggage, span.TagObjects,
                Events = span.Events.Select(item => new { item.Name, item.Tags }),
                Metrics = measurements.Select(point => point.Tags)
            });
            Assert.Multiple(() =>
            {
                Assert.That(response.StatusCode, Is.EqualTo(status));
                Assert.That(log.GetProperty("http.route").GetString(), Is.EqualTo(route));
                Assert.That(log.GetProperty("http.request.method").GetString(), Is.EqualTo(method));
                Assert.That(log.GetProperty("category").GetString(), Is.EqualTo(outcome));
                Assert.That(log.GetProperty("traceId").GetString(), Is.EqualTo(TraceId));
                Assert.That(exportedLogs, Has.Some.Contains(outcome));
                Assert.That(span.TraceId.ToString(), Is.EqualTo(TraceId));
                Assert.That(span.ParentSpanId.ToString(), Is.EqualTo(ParentSpanId));
                Assert.That(span.DisplayName, Is.EqualTo(route == AuthenticationRoute.Unknown ? "authentication" : $"{method} {route}"));
                Assert.That(span.GetTagItem("http.route"), Is.EqualTo(route));
                Assert.That(span.GetTagItem("http.request.method"), Is.EqualTo(method));
                Assert.That(span.Status, Is.EqualTo(fails ? ActivityStatusCode.Error : ActivityStatusCode.Unset));
                if (fails) Assert.That(span.Events.Single().Tags.Single(tag => tag.Key == "exception.message").Value, Is.EqualTo("Falha durante a autenticação."));
                Assert.That(measurements.Select(point => point.Name), Is.EquivalentTo(new[] { "mecanica.auth.invocations", "mecanica.auth.invocation.duration" }));
                foreach (var (_, tags) in measurements)
                {
                    Assert.That(tags.Keys, Is.EquivalentTo(new[] { "http.route", "http.request.method", "outcome", "http.response.status_code" }));
                    Assert.That(tags["http.route"], Is.EqualTo(route));
                    Assert.That(tags["http.request.method"], Is.EqualTo(method));
                    Assert.That(tags["outcome"], Is.EqualTo(outcome));
                }
                foreach (var secret in new[] { Password, IncomingToken, IssuedToken, Code, Document, Failure, Unknown, UnknownMethod, "private-trace-state", "private-baggage" })
                    Assert.That(serializedSignals, Does.Not.Contain(secret));
                if (fails) Assert.That(response.Body, Does.Not.Contain(Failure).And.Not.Contain(Password));
            });
        }
        finally
        {
            Sdk.SetDefaultTextMapPropagator(originalPropagator);
        }
    }

    private static ConfigurationRoot Configuration() => (ConfigurationRoot)new ConfigurationBuilder()
        .SetBasePath(TestContext.CurrentContext.TestDirectory)
        .AddJsonFile("Observability/observability.json")
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Telemetry:Enabled"] = "true", ["Runtime:Environment"] = "hom", ["AWS_REGION"] = "us-east-1",
            ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:4319"
        })
        .Build();

    private sealed class TestExporter<T>(Action<T> capture) : BaseExporter<T> where T : class
    {
        public override ExportResult Export(in Batch<T> batch)
        {
            foreach (var item in batch) capture(item);
            return ExportResult.Success;
        }
    }
}
