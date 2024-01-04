using AzurePolicyEvaluator;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using System.CommandLine;

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

var policyOption = new Option<FileInfo?>("--policy") { Description = "Policy file to evaluate" };
policyOption.AddAlias("-p");

var testOption = new Option<FileInfo?>("--test") { Description = "Test file to use in evaluation" };
testOption.AddAlias("-t");

var watchOption = new Option<bool>("--watch") { Description = "Watch current folder for policy changes" };
watchOption.AddAlias("-w");

var rootCommand = new RootCommand("Azure Policy Evaluator")
{
    policyOption,
    testOption,
    watchOption
};

rootCommand.SetHandler((policyFile, testFile, watch) =>
{
    if (watch)
    {
        Console.WriteLine("Watching for policy changes...");
    }
    else if (policyFile != null && testFile != null &&
             policyFile.Exists && testFile.Exists)
    {
        var policy = File.ReadAllText(policyFile.FullName);
        var test = File.ReadAllText(testFile.FullName);

        var evaluator = serviceProvider.GetRequiredService<Evaluator>();
        var evaluationResult = evaluator.Evaluate(policy, test);

        Console.WriteLine($"Policy {Path.GetFileNameWithoutExtension(policyFile.Name)} with test {Path.GetFileNameWithoutExtension(testFile.Name)} resulted to {(evaluationResult.Condition ? evaluationResult.Effect : PolicyConstants.Effects.None)}");
    }
    else
    {
        Console.WriteLine("Required arguments missing.");
        Console.WriteLine("Try '--help' for more information.");
    }

}, policyOption, testOption, watchOption);

await rootCommand.InvokeAsync(args);
