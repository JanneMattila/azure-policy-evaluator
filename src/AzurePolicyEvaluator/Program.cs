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

using var loggerFactory = serviceProvider.GetService<ILoggerFactory>();
var logger = loggerFactory.CreateLogger<Program>();

var policyOption = new Option<FileInfo?>("--policy") { Description = "Policy file to evaluate" };
policyOption.AddAlias("-p");

var testOption = new Option<FileInfo?>("--test") { Description = "Test file to use in evaluation" };
testOption.AddAlias("-t");

var watchOption = new Option<bool>("--watch") { Description = "Watch current folder for policy changes" };
watchOption.AddAlias("-w");

const string POLICY_FILE_NAME = "azurepolicy";
const string EXTENSION = "json";

var rootFolder = Directory.GetCurrentDirectory();

var rootCommand = new RootCommand(@"Azure Policy Evaluator allows you to evaluate Azure Policy files against test files.
You can use this to test your policies before deploying them to Azure.

The tool can be used in two ways:

1. Evaluate a single policy file against a single test file.
2. Watch for policy changes in the folders and evaluate them against all test files in the sub-folders.

More information can be found here:
https://github.com/JanneMattila/azure-policy-evaluator")
{
    policyOption,
    testOption,
    watchOption
};

rootCommand.SetHandler(async (policyFile, testFile, watch) =>
{
    if (watch)
    {
        logger.LogInformation("Watching for policy changes...");
        var watcher = new FileSystemWatcher(rootFolder, "*.json");
        watcher.Changed += PolicyFilesChanged;
        watcher.NotifyFilter = NotifyFilters.LastWrite;
        watcher.IncludeSubdirectories = true;
        watcher.EnableRaisingEvents = true;

        await Task.Delay(-1);
    }
    else if (policyFile != null && testFile != null &&
             policyFile.Exists && testFile.Exists)
    {
        var policy = File.ReadAllText(policyFile.FullName);
        var test = File.ReadAllText(testFile.FullName);

        var evaluator = serviceProvider.GetRequiredService<Evaluator>();
        var evaluationResult = evaluator.Evaluate(policy, test);

        var actual = (evaluationResult.Condition ? evaluationResult.Effect : PolicyConstants.Effects.None);
        var expected = GetExpectedResult(testFile.FullName);
        var result = OutputResult(actual, expected);
        logger.LogInformation($"Policy '{Path.GetFileNameWithoutExtension(policyFile.Name)}' with test '{Path.GetFileNameWithoutExtension(testFile.Name)}' resulted to '{actual}', '{expected}' was expected -> {result}");
    }
    else
    {
        Console.WriteLine("Required arguments missing.");
        Console.WriteLine("Try '--help' for more information.");
    }

}, policyOption, testOption, watchOption);

await rootCommand.InvokeAsync(args);

string GetExpectedResult(string testFile)
{
    var name = Path.GetFileNameWithoutExtension(testFile);
    var index = name.LastIndexOf('-');
    return name.Substring(index + 1);
}

string OutputResult(string actual, string expected)
{
    return string.Compare(actual, expected, StringComparison.InvariantCultureIgnoreCase) == 0 ? "PASS" : "FAIL";
}


void PolicyFilesChanged(object sender, FileSystemEventArgs e)
{
    var policyFilename = e.FullPath;
    List<string> testFiles = [];
    if (Path.GetFileNameWithoutExtension(e.Name) == POLICY_FILE_NAME)
    {
        // Azure Policy file has been changed. Look for test files in sub-folders.
        var policyFolder = Directory.GetParent(policyFilename);
        testFiles = Directory.GetFiles(policyFolder.FullName, $"*.{EXTENSION}", SearchOption.AllDirectories)
            .Where(f => Path.GetFileNameWithoutExtension(f) != POLICY_FILE_NAME)
            .ToList();
    }
    else
    {
        // Test file has been changed. Look for policy file in parent folder.
        var testFile = new FileInfo(policyFilename);
        testFiles.Add(testFile.FullName);
        string policyFile = null;

        var directory = testFile.Directory;
        while (directory.FullName.Length >= rootFolder.Length)
        {
            logger.LogInformation($"Looking for policy file in {directory.FullName}...");
            policyFile = Directory.GetFiles(directory.FullName, $"{POLICY_FILE_NAME}.{EXTENSION}").FirstOrDefault();
            if (policyFile != null)
            {
                policyFilename = policyFile;
                break;
            }
            directory = directory.Parent;
        }

        if (policyFile == null)
        {
            logger.LogInformation($"Could not find policy file. Test file '{Path.GetFileNameWithoutExtension(testFile.Name)}' has been changed.");
            return;
        }
        policyFilename = policyFile;
    }

    logger.LogInformation($"Evaluating policy {Path.GetFileNameWithoutExtension(policyFilename)}...");
    var policy = SafeFileRead(policyFilename);

    foreach (var testFile in testFiles)
    {
        var test = SafeFileRead(testFile);

        var evaluator = serviceProvider.GetRequiredService<Evaluator>();
        var evaluationResult = evaluator.Evaluate(policy, test);

        var actual = (evaluationResult.Condition ? evaluationResult.Effect : PolicyConstants.Effects.None);
        var expected = GetExpectedResult(testFile);
        var result = OutputResult(actual, expected);
        logger.LogInformation($"Policy '{Path.GetFileNameWithoutExtension(policyFilename)}' with test '{Path.GetFileNameWithoutExtension(testFile)}' resulted to '{actual}', '{expected}' was expected -> {result}");
    }
};

static string SafeFileRead(string file)
{
    for (int i = 0; i < 10; i++)
    {
        try
        {
            return File.ReadAllText(file);
        }
        catch (IOException)
        {
        }

        Console.WriteLine($"Could not read file '{file}'. Retrying {i + 1}...");
        Thread.Sleep(500);
    }
    return string.Empty;
}