using AzurePolicyEvaluator;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

Console.WriteLine("Azure Policy Evaluator");

var services = new ServiceCollection();
services.AddLogging(builder => {
    builder.SetMinimumLevel(LogLevel.Trace);
    builder.AddSimpleConsole(options =>
    {
        options.ColorBehavior = LoggerColorBehavior.Enabled;
        options.IncludeScopes = true;
        options.SingleLine = true;
        options.TimestampFormat = "HH:mm:ss ";
    });
});
services.AddSingleton<Evaluator>();
IServiceProvider serviceProvider = services.BuildServiceProvider();

var evaluator = serviceProvider.GetRequiredService<Evaluator>();

var policyFile = args[0];
var testFile = args[1];

var policy = File.ReadAllText(policyFile);
var test = File.ReadAllText(testFile);

var evaluationResult = evaluator.Evaluate(policy, test);

Console.WriteLine($"Policy {Path.GetFileNameWithoutExtension(policyFile)} with test {Path.GetFileNameWithoutExtension(testFile)} resulted to {(evaluationResult.Condition ? evaluationResult.Effect : "No effect")}");
