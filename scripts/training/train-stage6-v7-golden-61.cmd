@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0..\.."
pushd "%PROJECT_ROOT%" || exit /b 1

set ENABLE_NLP=true
set ENABLE_7ASECURITY_INDEX_ALIGNMENT=true
set ENABLE_GENERIC_INDEX_ALIGNMENT=true
set NLP_TIMEOUT_MS=120000

if not exist data\golden-reports\manifest.json (
  echo ERROR: data\golden-reports\manifest.json not found.
  popd
  exit /b 1
)

if not exist nlp_engine\train.py (
  echo ERROR: nlp_engine\train.py not found.
  popd
  exit /b 1
)

echo.
echo === 1/5 Verify current 61 golden before training ===
call npm run golden:eval:strict
if errorlevel 1 (
  echo ERROR: Golden eval failed before training. Stop.
  popd
  exit /b 1
)

echo.
echo === 2/5 Export golden reports to NLP training JSON ===
call npx tsx scripts\training\export-golden-to-nlp.ts
if errorlevel 1 (
  echo ERROR: Golden NLP export failed. Stop.
  popd
  exit /b 1
)

echo.
echo === 3/5 Train / fine-tune NLP model ===
pushd nlp_engine || exit /b 1

if exist .venv\Scripts\activate.bat (
  call .venv\Scripts\activate.bat
)

python -m pip install -r requirements.txt
if errorlevel 1 (
  echo ERROR: pip install failed. Stop.
  popd
  popd
  exit /b 1
)

set "BASE_MODEL=models\cyberbert-ner"
if not exist "!BASE_MODEL!\config.json" set "BASE_MODEL=models\cyberbert-ner-v5-real-aug"
if not exist "!BASE_MODEL!\config.json" set "BASE_MODEL=jackaduma/SecBERT"

echo Base model: !BASE_MODEL!

python train.py ^
  --processed_json data\processed\processed_reports_stage6_v7_gold.json ^
  --output_dir models\cyberbert-ner-stage6-v7-61 ^
  --processed_dataset_dir data\processed\dataset_stage6_v7_gold ^
  --save_dataset ^
  --overwrite_output_dir ^
  --model_name "!BASE_MODEL!" ^
  --epochs 5 ^
  --batch_size 4 ^
  --eval_batch_size 4 ^
  --gradient_accumulation_steps 2 ^
  --lr 1e-5 ^
  --weight_decay 0.01 ^
  --warmup_ratio 0.06 ^
  --loss_type focal ^
  --class_weighting sqrt ^
  --o_label_weight 0.25 ^
  --max_class_weight 10 ^
  --max_length 512 ^
  --stride 128 ^
  --early_stopping_patience 2

if errorlevel 1 (
  echo ERROR: Training failed. Existing model was not replaced.
  popd
  popd
  exit /b 1
)

echo.
echo === 4/5 Install trained model as production model_dir ===
if exist models\cyberbert-ner-backup-before-stage6-v7-61 rmdir /S /Q models\cyberbert-ner-backup-before-stage6-v7-61
if exist models\cyberbert-ner xcopy /E /I /Y models\cyberbert-ner models\cyberbert-ner-backup-before-stage6-v7-61 >nul
if exist models\cyberbert-ner rmdir /S /Q models\cyberbert-ner
xcopy /E /I /Y models\cyberbert-ner-stage6-v7-61 models\cyberbert-ner >nul
if errorlevel 1 (
  echo ERROR: Could not copy trained model to models\cyberbert-ner.
  popd
  popd
  exit /b 1
)

popd

echo.
echo === 5/5 Verify app golden eval with trained model ===
call npm run golden:eval:strict
if errorlevel 1 (
  echo ERROR: Golden eval failed after installing trained model.
  echo Restore backup from nlp_engine\models\cyberbert-ner-backup-before-stage6-v7-61 if needed.
  popd
  exit /b 1
)

echo.
echo Training complete. Model installed at nlp_engine\models\cyberbert-ner
popd
endlocal
