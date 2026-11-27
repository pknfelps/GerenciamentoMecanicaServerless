using OpenTelemetry;
using System.Diagnostics;

namespace GerenciamentoMecanica.Autenticacao.Function.Observability;

public sealed class SafeTraceProcessor(TelemetryCollectionOptions collection) : BaseProcessor<Activity>
{
    internal const string RouteProperty = "Mecanica.Auth.Route";
    internal const string MethodProperty = "Mecanica.Auth.Method";

    public override void OnEnd(Activity activity)
    {
        var database = activity.Source.Name == "Npgsql";
        var allowed = database ? collection.DatabaseAttributes : collection.InvocationAttributes;
        foreach (var tag in activity.TagObjects.Where(tag => !allowed.Contains(tag.Key)).ToArray())
            activity.SetTag(tag.Key, null);
        foreach (var item in activity.Baggage.ToArray())
            activity.SetBaggage(item.Key, null);
        activity.TraceStateString = null;

        foreach (ref var item in activity.EnumerateEvents())
        {
            var eventName = item.Name;
            var tags = new ActivityTagsCollection(item.Tags.Where(tag =>
                eventName == "exception" && tag.Value is not null && collection.ExceptionAttributes.Contains(tag.Key)));
            if (tags.ContainsKey("exception.message"))
                tags["exception.message"] = database ? collection.DatabaseErrorMessage : collection.InvocationErrorMessage;
            item = new ActivityEvent("exception", item.Timestamp, tags);
        }

        if (database)
            activity.DisplayName = collection.DatabaseSpanName;
        else
        {
            var route = activity.GetCustomProperty(RouteProperty) as string ?? Http.AuthenticationRoute.Unknown;
            var method = activity.GetCustomProperty(MethodProperty) as string ?? "OTHER";
            activity.DisplayName = route == Http.AuthenticationRoute.Unknown ? collection.InvocationSpanName : $"{method} {route}";
            activity.SetTag("http.request.method", method);
            activity.SetTag("http.route", route);
        }
        if (activity.Status == ActivityStatusCode.Error)
            activity.SetStatus(ActivityStatusCode.Error, database
                ? collection.DatabaseErrorMessage : collection.InvocationErrorMessage);
    }
}
