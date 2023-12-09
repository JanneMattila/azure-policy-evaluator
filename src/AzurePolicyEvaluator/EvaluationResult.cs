using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzurePolicyEvaluator;

public class EvaluationResult
{
    public bool IsSuccess { get; set; } = false;

    public string EvaluationPath { get; set; } = string.Empty;

    public string Result { get; set; } = string.Empty;

    public string Details { get; set; } = string.Empty;
}
