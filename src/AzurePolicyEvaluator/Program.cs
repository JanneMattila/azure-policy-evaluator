using AzurePolicyEvaluator;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using System.CommandLine;

IServiceProvider serviceProvider;
ILogger<Program> logger;
var lastWriteTime = DateTime.MinValue;

var policyOption = new Option<FileInfo?>("--policy") { Description = "Policy file to evaluate" };
policyOption.AddAlias("-p");

var testOption = new Option<FileInfo?>("--test") { Description = "Test file to use in evaluation" };
testOption.AddAlias("-t");

var watchOption = new Option<bool>("--watch") { Description = "Watch for policy changes" };
watchOption.AddAlias("-w");

var watchFolderOption = new Option<string>("--watch-folder") { Description = "Watch folder path" };
watchFolderOption.AddAlias("-f");

var runTestsOption = new Option<string>("--run-tests") { Description = "Run all tests from path" };
runTestsOption.AddAlias("-r");

var loggingOption = new Option<string>(
    "--logging",
    "Logging verbosity")
        .FromAmong(
            "trace",
            "debug",
            "info");
loggingOption.SetDefaultValue("info");

const string POLICY_FILE_NAME = "azurepolicy";
const string EXTENSION = "json";

int returnCode = 0;
var rootFolder = Directory.GetCurrentDirectory();

var rootCommand = new RootCommand(@"Azure Policy Evaluator allows you to evaluate Azure Policy files against test files.
You can use this to test your policies before deploying them to Azure.

Tool can be used in 3 different ways:

1. Evaluate a single policy file against a single test file.
2. Watch for policy changes in the folders and evaluate them against all test files in the sub-folders.
3. Run all tests from a folder.

More information can be found here:
https://github.com/JanneMattila/azure-policy-evaluator")
{
    policyOption,
    testOption,
    watchOption,
    watchFolderOption,
    runTestsOption,
    loggingOption
};

rootCommand.SetHandler(async (policyFile, testFile, watch, folder, runTestsFolder, logging) =>
{
    var loggingLevel = logging switch
    {
        "trace" => LogLevel.Trace,
        "debug" => LogLevel.Debug,
        "info" => LogLevel.Information,
        _ => LogLevel.Information
    };

    var services = new ServiceCollection();
    services.AddLogging(builder => {
        builder.SetMinimumLevel(loggingLevel);
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ConsoleFormatter, CustomConsoleFormatter>());
        builder.AddConsole(options =>
            {
                options.MaxQueueLength = 1;
                options.FormatterName = "custom";
            });
    });
    services.AddSingleton<AliasRepository>();
    services.AddSingleton<Evaluator>();
    serviceProvider = services.BuildServiceProvider();

    using var loggerFactory = serviceProvider.GetService<ILoggerFactory>();
    ArgumentNullException.ThrowIfNull(loggerFactory);

    logger = loggerFactory.CreateLogger<Program>();

    if (watch)
    {
        if (!string.IsNullOrEmpty(folder))
        {
            var path = Path.GetFullPath(folder);
            if (!Directory.Exists(path))
            {
                logger.LogError("Folder '{Path}' does not exist.", path);
                return;
            }
            rootFolder = path;
        }
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
        if (!CreateEvaluationReport(policyFile.FullName, testFile.FullName, evaluationResult))
        {
            returnCode = -1;
        }
    }
    else if (!string.IsNullOrEmpty(runTestsFolder))
    {
        var path = Path.GetFullPath(runTestsFolder);
        if (!Directory.Exists(runTestsFolder))
        {
            logger.LogError("Folder '{Path}' does not exist.", path);
            return;
        }
        rootFolder = path;

        var policyFiles = Directory.GetFiles(rootFolder, $"{POLICY_FILE_NAME}.{EXTENSION}", SearchOption.AllDirectories);
        foreach (var file in policyFiles)
        {
            var value = ProcessChangedFile(file);
            if (value == null || value == false)
            {
                returnCode = -1;
            }
        }
    }
    else
    {
        Console.WriteLine("Required arguments missing.");
        Console.WriteLine("Try '--help' for more information.");
    }
}, policyOption, testOption, watchOption, watchFolderOption, runTestsOption, loggingOption);

await rootCommand.InvokeAsync(args);

return returnCode;

string GetExpectedResult(string testFile)
{
    var name = Path.GetFileNameWithoutExtension(testFile);
    var index = name.LastIndexOf('-');
    return name.Substring(index + 1);
}

bool CreateEvaluationReport(string policyFile, string testFile, EvaluationResult evaluationResult)
{
    var actual = (evaluationResult.Condition ? evaluationResult.Effect : PolicyConstants.Effects.None);
    var expected = GetExpectedResult(testFile);

    bool resultOk = true;
    var policy = Path.GetFileNameWithoutExtension(policyFile);
    var test = Path.GetFileNameWithoutExtension(testFile);

    if (string.Compare(actual, expected, StringComparison.InvariantCultureIgnoreCase) == 0)
    {
        logger.LogInformation("Policy '{Policy}' with test '{Test}' evaluated to '{Actual}' which was expected -> '{Result}'", policy, test, actual, "PASS");
    }
    else
    {
        logger.LogError("Policy '{Policy}' with test '{Test}' evaluated to '{Actual}' which was not the expected '{Expected}' -> '{Result}'", policy, test, actual, expected, "FAIL");
        resultOk = false;
    }

    return resultOk;
}

void PolicyFilesChanged(object sender, FileSystemEventArgs e)
{
    if (lastWriteTime.AddMilliseconds(100) < File.GetLastWriteTime(e.FullPath))
    {
        lastWriteTime = File.GetLastWriteTime(e.FullPath);
    }
    else
    {
        // File has been changed, but it was the same change that we already processed.
        return;
    }

    logger.LogInformation($"Policy files changed");

    ProcessChangedFile(e.FullPath);
}

bool? ProcessChangedFile(string fullPath)
{
    var resultOk = true;
    try
    {
        var name = Path.GetFileNameWithoutExtension(fullPath);
        var policyFilename = fullPath;
        List<string> testFiles = [];
        if (Path.GetFileNameWithoutExtension(name) == POLICY_FILE_NAME)
        {
            // Azure Policy file has been changed. Look for test files in sub-folders.
            var policyFolder = Directory.GetParent(policyFilename);
            ArgumentNullException.ThrowIfNull(policyFolder);

            testFiles = Directory.GetFiles(policyFolder.FullName, $"*.{EXTENSION}", SearchOption.AllDirectories)
                .Where(f => Path.GetFileNameWithoutExtension(f) != POLICY_FILE_NAME)
                .ToList();
        }
        else
        {
            // Test file has been changed. Look for policy file in parent folder.
            var testFile = new FileInfo(policyFilename);
            testFiles.Add(testFile.FullName);
            string? policyFile = null;

            var directory = testFile.Directory;
            ArgumentNullException.ThrowIfNull(directory);

            while (directory.FullName.Length >= rootFolder.Length)
            {
                logger.LogDebug($"Looking for policy file in {directory.FullName}...");
                policyFile = Directory.GetFiles(directory.FullName, $"{POLICY_FILE_NAME}.{EXTENSION}").FirstOrDefault();
                if (policyFile != null)
                {
                    policyFilename = policyFile;
                    break;
                }
                directory = directory.Parent;
                ArgumentNullException.ThrowIfNull(directory);
            }

            if (policyFile == null)
            {
                logger.LogWarning($"Could not find policy file. Test file '{Path.GetFileNameWithoutExtension(testFile.Name)}' has been changed.");
                return null;
            }
            policyFilename = policyFile;
        }

        logger.LogDebug($"Evaluating policy {Path.GetFileNameWithoutExtension(policyFilename)}...");
        var policy = SafeFileRead(policyFilename);

        foreach (var testFile in testFiles)
        {
            var test = SafeFileRead(testFile);

            var evaluator = serviceProvider.GetRequiredService<Evaluator>();
            var evaluationResult = evaluator.Evaluate(policy, test);

            if (!CreateEvaluationReport(policyFilename, testFile, evaluationResult))
            {
                resultOk = false;
            }
        }
    }
    catch (Exception ex)
    {
        logger.LogCritical(ex, "Error while evaluating policy files.");
    }
    return resultOk;
}

string SafeFileRead(string file)
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

        logger.LogDebug($"Could not read file '{file}'. Retrying {i + 1}...");
        Thread.Sleep(500);
    }
    return string.Empty;
}