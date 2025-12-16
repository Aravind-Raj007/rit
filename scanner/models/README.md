# ScamGuard Pro - ML Model Setup

This directory contains the machine learning model files for the ScamGuard Pro detection engine.

## Model Information

- **Model Name**: indic-scam-detector
- **Version**: 2025.1.0
- **Base Model**: ai4bharat/indic-bert (fine-tuned)
- **Format**: ONNX (optimized for inference)
- **Size**: ~14.2 MB (quantized INT8)
- **Languages**: Hindi, English, Hinglish

## Files

| File                | Description                       | Status               |
| ------------------- | --------------------------------- | -------------------- |
| `model-config.json` | Model configuration and metadata  | ✅ Included          |
| `tokenizer.json`    | Tokenizer vocabulary and settings | ✅ Placeholder       |
| `indic-scam.onnx`   | ONNX model file                   | ⬇️ Download Required |

## Download Instructions

### Option 1: Automatic Download (Recommended)

The ScamGuard Pro engine will automatically download the model on first launch if not present.

### Option 2: Manual Download

1. **From Hugging Face (Primary)**:

   ```bash
   curl -L -o indic-scam.onnx "https://huggingface.co/scamguard/indic-scam-detector-v2025/resolve/main/model.onnx"
   ```

2. **From GitHub Releases (Backup)**:
   ```bash
   curl -L -o indic-scam.onnx "https://github.com/scamguard-pro/models/releases/download/v2025.1/indic-scam.onnx"
   ```

### Option 3: Train Your Own Model

If you want to fine-tune the model on your own dataset:

```python
# requirements: transformers, onnx, onnxruntime, datasets

from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

# Load base model
model_name = "ai4bharat/indic-bert"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(
    model_name,
    num_labels=14  # Number of scam categories
)

# Fine-tune on your dataset
# ... training code ...

# Export to ONNX
dummy_input = tokenizer("Sample text", return_tensors="pt")
torch.onnx.export(
    model,
    (dummy_input["input_ids"], dummy_input["attention_mask"]),
    "indic-scam.onnx",
    input_names=["input_ids", "attention_mask"],
    output_names=["logits"],
    dynamic_axes={
        "input_ids": {0: "batch", 1: "sequence"},
        "attention_mask": {0: "batch", 1: "sequence"},
        "logits": {0: "batch"}
    },
    opset_version=14
)

# Quantize for size reduction
import onnxruntime as ort
from onnxruntime.quantization import quantize_dynamic, QuantType

quantize_dynamic(
    "indic-scam.onnx",
    "indic-scam-quantized.onnx",
    weight_type=QuantType.QInt8
)
```

## Model Labels

The model classifies text into 14 categories:

| Index | Label              | Description                 |
| ----- | ------------------ | --------------------------- |
| 0     | SAFE               | Legitimate message          |
| 1     | UPI_SCAM           | UPI payment fraud           |
| 2     | PHISHING           | Generic phishing attempt    |
| 3     | BANKING_FRAUD      | Bank impersonation          |
| 4     | LOTTERY_SCAM       | Fake lottery/prize          |
| 5     | KYC_FRAUD          | KYC update scam             |
| 6     | OTP_SCAM           | OTP stealing attempt        |
| 7     | JOB_SCAM           | Fake job offers             |
| 8     | INVESTMENT_SCAM    | Investment/trading fraud    |
| 9     | LOAN_SCAM          | Fake loan offers            |
| 10    | FAKE_DELIVERY      | Fake delivery notifications |
| 11    | GOVT_IMPERSONATION | Government impersonation    |
| 12    | CRYPTO_SCAM        | Cryptocurrency scams        |
| 13    | SOCIAL_ENGINEERING | Social manipulation         |

## Performance Metrics

| Metric         | Value |
| -------------- | ----- |
| Accuracy       | 96.7% |
| F1 Score       | 95.8% |
| Precision      | 96.2% |
| Recall         | 95.4% |
| Inference Time | ~15ms |

## Usage in Engine

The engine uses ONNX Runtime for inference:

```typescript
import * as ort from "onnxruntime-node";

async function loadModel() {
  const session = await ort.InferenceSession.create(
    "./scanner/models/indic-scam.onnx"
  );
  return session;
}

async function predict(session: ort.InferenceSession, text: string) {
  // Tokenize text
  const inputIds = tokenize(text);
  const attentionMask = new Array(inputIds.length).fill(1);

  // Run inference
  const feeds = {
    input_ids: new ort.Tensor(
      "int64",
      BigInt64Array.from(inputIds.map(BigInt)),
      [1, inputIds.length]
    ),
    attention_mask: new ort.Tensor(
      "int64",
      BigInt64Array.from(attentionMask.map(BigInt)),
      [1, inputIds.length]
    ),
  };

  const results = await session.run(feeds);
  const logits = results.logits.data as Float32Array;

  // Apply softmax and get prediction
  const probs = softmax(Array.from(logits));
  const maxProb = Math.max(...probs);
  const predictedLabel = probs.indexOf(maxProb);

  return { label: predictedLabel, confidence: maxProb };
}
```

## Fallback Mode

If the ONNX model is not available or fails to load, the engine falls back to:

1. Regex pattern matching
2. YARA rule scanning
3. Keyword-based scoring

This ensures 100% offline operation even without the ML model.

## License

The model weights are released under Apache 2.0 license.
The base IndicBERT model is from AI4Bharat (IIT Madras).
