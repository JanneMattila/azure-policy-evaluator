using AzurePolicyEvaluator;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

Console.WriteLine("Azure Policy Evaluator");

var services = new ServiceCollection();
services.AddLogging(builder => builder.AddConsole());
services.AddSingleton<Evaluator>();
IServiceProvider serviceProvider = services.BuildServiceProvider();

var evaluator = serviceProvider.GetRequiredService<Evaluator>();

var policyFile = args[0];
var testFile = args[1];

var policy = File.ReadAllText(policyFile);
var test = File.ReadAllText(testFile);

var evaluationResult = evaluator.Evaluate(policy, test);

Console.WriteLine($"Policy {Path.GetFileNameWithoutExtension(policyFile)} with test {Path.GetFileNameWithoutExtension(testFile)} resulted to {(evaluationResult.Condition ? evaluationResult.Effect : "No effect")}");
