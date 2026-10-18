# Hugging Face integration

This directory provides publishing and experiment guidance; it does not imply that a model has been trained or uploaded by this project.

## Recommended Hub layout

1. **Code repository**: publish the source archive on your Git hosting platform.
2. **Dataset repository**: publish only sanitized JSONL/CSV evidence and schema documentation; keep raw host paths and secrets out.
3. **Model repository**: create only if you actually produce model weights or adapters. ModelBoundary Lab itself is tooling, not a pretrained model.
4. Link the Zenodo record in each relevant README/model/dataset card: https://doi.org/10.5281/zenodo.23442798.

## Dataset card template

Copy `DATASET_CARD.md` into the dataset repository's `README.md`, and update the repository name, record counts, license, and provenance to match the uploaded files. Never claim records are empirical if they are synthetic.

## Model card template

Copy `MODEL_CARD_TEMPLATE.md` only if you publish actual weights. Fill in base model, immutable revision, training/fine-tuning method, dataset provenance, evaluation metrics, limitations, and the upstream license. Do not upload third-party weights without checking redistribution terms.

## Controlled model smoke test

Use `../../experiments/run_real_model_smoke_test.py`. Pin the full commit SHA returned by the Hub, use `trust_remote_code=False`, and retain the JSON output locally. The smoke test does not evaluate the sandbox or prove confidentiality. Avoid public upload of generated outputs if prompts may be sensitive.

## Upload through the web UI

Create a dataset repo at https://huggingface.co/new?repoType=dataset, then upload the sanitized data files and `DATASET_CARD.md` as `README.md`. Hugging Face's official documentation describes repository creation and uploads: https://huggingface.co/docs/hub/datasets-adding.
