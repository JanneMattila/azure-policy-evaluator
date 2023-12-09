using AzurePolicyEvaluator;

Console.WriteLine("Azure Policy Evaluator");

var policy = File.ReadAllText(args[0]);
var test = File.ReadAllText(args[1]);

var evaluator = new Evaluator();
var evaluationResult = evaluator.Evaluate(policy, test);
Console.WriteLine(evaluationResult.IsSuccess);

