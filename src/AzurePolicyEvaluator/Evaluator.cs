using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzurePolicyEvaluator;

public class Evaluator
{
    public async Task<EvaluationResult> EvaluateAsync(string policy, string test)
    {
        return await Task.FromResult(new EvaluationResult());
    }
}
