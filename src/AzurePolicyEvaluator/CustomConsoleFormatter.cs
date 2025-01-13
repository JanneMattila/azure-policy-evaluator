using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Logging;
using System.Text;

namespace AzurePolicyEvaluator;

// CustomConsoleFormatter.cs
// This file contains the implementation of the CustomConsoleFormatter class, which extends the ConsoleFormatter class
// from Microsoft.Extensions.Logging.Console. The CustomConsoleFormatter provides a custom console logging format
// with color-coded log levels. It follows the implementation pattern of SimpleConsoleFormatter.cs from the .NET runtime.
// The class defines a set of colors for different log levels and overrides the Write method to format log messages
// with these colors and additional context information.

/// <summary>
/// This implementation strongly follows the SimpleConsoleFormatter.cs implementation:
/// https://github.com/dotnet/runtime/blob/main/src/libraries/Microsoft.Extensions.Logging.Console/src/SimpleConsoleFormatter.cs
/// </summary>
public class CustomConsoleFormatter : ConsoleFormatter
{
    record ConsoleColors(ConsoleColor? Background, ConsoleColor? Foreground);

    private static readonly Dictionary<LogLevel, ConsoleColors> _logLevelColors = new()
    {
        [LogLevel.Trace] = new ConsoleColors(null, ConsoleColor.Gray),
        [LogLevel.Debug] = new ConsoleColors(null, ConsoleColor.Gray),
        [LogLevel.Information] = new ConsoleColors(null, null),
        [LogLevel.Warning] = new ConsoleColors(null, ConsoleColor.Yellow),
        [LogLevel.Error] = new ConsoleColors(null, ConsoleColor.Red),
        [LogLevel.Critical] = new ConsoleColors(null, ConsoleColor.Red),
    };

    public CustomConsoleFormatter() : base("custom")
    {
    }

    public override void Write<TState>(in LogEntry<TState> logEntry, IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        string message = logEntry.Formatter(logEntry.State, logEntry.Exception);
        if (logEntry.Exception == null && message == null)
        {
            return;
        }

        var category =  logEntry.LogLevel switch
        {
            LogLevel.Trace => "TRACE",
            LogLevel.Warning => "WARNING",
            LogLevel.Error => "ERROR",
            LogLevel.Critical => "FATAL",
            _ => ""
        };

        var colors = _logLevelColors[logEntry.LogLevel];

        var sb = new StringBuilder();
        if (!string.IsNullOrEmpty(category))
        {
            sb.Append(category);
            sb.Append(' ');
        }

        scopeProvider?.ForEachScope((scope, state) =>
        {
            sb.Append($"{scope} => ");
        }, textWriter);

        sb.Append(message);
        if (logEntry.Exception != null)
        {
            sb.AppendLine();
            sb.Append($"{logEntry.Exception.GetType().Name}: {logEntry.Exception.Message} ");
            sb.Append($"{logEntry.Exception.StackTrace} ");
        }

        textWriter.WriteWithColor(sb.ToString(), colors.Background, colors.Foreground);
    }
}
