"""
CICIDS2017 Model Training - Compatible with IDPS Backend
Matches the original training methodology
"""

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import os, glob, zipfile
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support,confusion_matrix
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb
from imblearn.over_sampling import SMOTE
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# =============================================================================
# 1. EXTRACT AND LOAD DATA
# =============================================================================

archive_path = r"C:\Users\aksha\Documents\projects\project_sapience\CNN-LSTM\archive (2).zip"
extract_dir = r"C:\Users\aksha\Documents\projects\project_sapience\CNN-LSTM\data_cicids"

os.makedirs(extract_dir, exist_ok=True)
if os.path.exists(archive_path):
    with zipfile.ZipFile(archive_path, 'r') as z:
        z.extractall(extract_dir)
    print('✓ Extracted to', extract_dir)

def load_cicids_data(folder):
    csv_files = glob.glob(os.path.join(folder, '**', '*.csv'), recursive=True)
    parquet_files = glob.glob(os.path.join(folder, '**', '*.parquet'), recursive=True)
    all_files = sorted(csv_files) + sorted(parquet_files)
    print(f'Found {len(csv_files)} CSV files and {len(parquet_files)} Parquet files')
    
    dfs = []
    for f in all_files:
        try:
            if f.lower().endswith('.csv'):
                df = pd.read_csv(f, low_memory=False)
            else:
                df = pd.read_parquet(f)
            print(f'  Loaded {os.path.basename(f)}: {df.shape}')
            dfs.append(df)
        except Exception as e:
            print(f'  Failed: {f} -> {e}')
    
    data = pd.concat(dfs, ignore_index=True)
    print(f'✓ Combined shape: {data.shape}')
    return data

df = load_cicids_data(extract_dir)

# =============================================================================
# 2. DATA CLEANING
# =============================================================================

print('\n' + '='*70)
print('DATA CLEANING')
print('='*70)

print(f'Original shape: {df.shape}')
print(f'Original columns: {len(df.columns)}')
print('\nLabel distribution:')
print(df['Label'].value_counts())

# Drop high-NA columns
thresh = int(0.5 * len(df))
drop_cols = df.columns[df.isna().sum() > thresh].tolist()
if drop_cols:
    df.drop(columns=drop_cols, inplace=True)
    print(f'✓ Dropped {len(drop_cols)} high-NA columns')

# Drop constant columns
const_cols = df.columns[df.nunique() <= 1].tolist()
if const_cols:
    df.drop(columns=const_cols, inplace=True)
    print(f'✓ Dropped {len(const_cols)} constant columns')

# Handle infinities and NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f'✓ After cleaning: {df.shape}')

# =============================================================================
# 3. BALANCED SAMPLING (Like original code)
# =============================================================================

print('\n' + '='*70)
print('BALANCED SAMPLING')
print('='*70)

# Sample like the original code
df_minor = df[(df['Label']=='WebAttack')|(df['Label']=='Bot')|(df['Label']=='Infiltration')]
df_BENIGN = df[df['Label']=='Benign'].sample(frac=0.01, random_state=42)
df_DoS = df[df['Label']=='DoS']
df_PortScan = df[df['Label']=='PortScan']
df_BruteForce = df[df['Label']=='BruteForce']

df_s = pd.concat([df_BENIGN, df_DoS, df_PortScan, df_BruteForce, df_minor], ignore_index=True)
df_s = df_s.sample(frac=1, random_state=42)  # Shuffle

print('Sampled distribution:')
print(df_s['Label'].value_counts())
print(f'✓ Sampled shape: {df_s.shape}')

# Save sampled data
os.makedirs('data', exist_ok=True)
df_s.to_csv('data/CICIDS2017_sample.csv', index=False)
print('✓ Saved to data/CICIDS2017_sample.csv')

# =============================================================================
# 4. NORMALIZATION (Min-Max per feature)
# =============================================================================

print('\n' + '='*70)
print('FEATURE NORMALIZATION')
print('='*70)

# Get numeric features (exclude Label)
numeric_features = df_s.dtypes[df_s.dtypes != 'object'].index

# Store original min/max BEFORE normalization
feature_min = df_s[numeric_features].min().values
feature_max = df_s[numeric_features].max().values

# Min-max normalize each feature
df_s[numeric_features] = df_s[numeric_features].apply(
    lambda x: (x - x.min()) / (x.max() - x.min())
)
df_s = df_s.fillna(0)

print(f'✓ Normalized {len(numeric_features)} features')

# =============================================================================
# 5. ENCODE LABELS
# =============================================================================

labelencoder = LabelEncoder()
df_s['Label'] = labelencoder.fit_transform(df_s['Label'])

print('\n' + '='*70)
print('LABEL ENCODING')
print('='*70)
for i, label in enumerate(labelencoder.classes_):
    print(f'  {i}: {label}')

# =============================================================================
# 6. SPLIT DATA (80-20)
# =============================================================================

X = df_s.drop(['Label'], axis=1).values
y = df_s['Label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, train_size=0.8, test_size=0.2, random_state=0, stratify=y
)

print(f'\n✓ Train: {X_train.shape}, Test: {X_test.shape}')

# =============================================================================
# 7. APPLY SMOTE (Like original)
# =============================================================================

print('\n' + '='*70)
print('SMOTE RESAMPLING')
print('='*70)

# Find minority class
unique, counts = np.unique(y_train, return_counts=True)
min_class = unique[np.argmin(counts)]
min_count = counts[np.argmin(counts)]

print(f'Minority class: {labelencoder.classes_[min_class]} ({min_count} samples)')

# Apply SMOTE to balance minority class
target_count = int(min_count * 1.5)  # Increase minority by 50%
smote = SMOTE(sampling_strategy={min_class: target_count}, random_state=42)

y_train = y_train.astype(int)
y_test = y_test.astype(int)

X_train, y_train = smote.fit_resample(X_train, y_train)

print(f'✓ After SMOTE: {X_train.shape}')
print('Class distribution:')
unique, counts = np.unique(y_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f'  {labelencoder.classes_[u]}: {c}')

# =============================================================================
# 8. TRAIN BASE MODELS (WITHOUT feature selection first)
# =============================================================================

print('\n' + '='*70)
print('TRAINING BASE MODELS')
print('='*70)

# Decision Tree
print('\n1. Decision Tree...')
dt = DecisionTreeClassifier(random_state=0)
dt.fit(X_train, y_train)
dt_score = dt.score(X_test, y_test)
print(f'   Accuracy: {dt_score:.4f}')

dt_train = dt.predict(X_train)
dt_test = dt.predict(X_test)

# Random Forest
print('2. Random Forest...')
rf = RandomForestClassifier(random_state=0)
rf.fit(X_train, y_train)
rf_score = rf.score(X_test, y_test)
print(f'   Accuracy: {rf_score:.4f}')

rf_train = rf.predict(X_train)
rf_test = rf.predict(X_test)

# Extra Trees
print('3. Extra Trees...')
et = ExtraTreesClassifier(random_state=0)
et.fit(X_train, y_train)
et_score = et.score(X_test, y_test)
print(f'   Accuracy: {et_score:.4f}')

et_train = et.predict(X_train)
et_test = et.predict(X_test)

# XGBoost
print('4. XGBoost...')
xg = xgb.XGBClassifier(n_estimators=10, eval_metric='mlogloss')
xg.fit(X_train, y_train)
xg_score = xg.score(X_test, y_test)
print(f'   Accuracy: {xg_score:.4f}')

xg_train = xg.predict(X_train)
xg_test = xg.predict(X_test)

# =============================================================================
# 9. FEATURE IMPORTANCE & SELECTION (90% threshold)
# =============================================================================

print('\n' + '='*70)
print('FEATURE SELECTION')
print('='*70)

# Get feature importances
dt_feature = dt.feature_importances_
rf_feature = rf.feature_importances_
et_feature = et.feature_importances_
xgb_feature = xg.feature_importances_

# Average importance
avg_feature = (dt_feature + rf_feature + et_feature + xgb_feature) / 4

# Get feature names
feature_names = df_s.drop(['Label'], axis=1).columns.values

# Sort by importance
f_list = sorted(zip(avg_feature, feature_names), reverse=True)

print('Top 10 features:')
for i, (score, name) in enumerate(f_list[:10]):
    print(f'  {i+1}. {name}: {score:.4f}')

# Select features until 90% importance
Sum = 0
selected_features = []
for score, name in f_list:
    Sum += score
    selected_features.append(name)
    if Sum >= 0.9:
        break

print(f'\n✓ Selected {len(selected_features)} features (90% importance)')

# =============================================================================
# 10. RETRAIN WITH SELECTED FEATURES
# =============================================================================

print('\n' + '='*70)
print('RETRAINING WITH SELECTED FEATURES')
print('='*70)

# Get indices of selected features
all_features = list(df_s.drop(['Label'], axis=1).columns)
selected_indices = [all_features.index(f) for f in selected_features]

# Select features from training data
X_train_fs = X_train[:, selected_indices]
X_test_fs = X_test[:, selected_indices]

# Get min/max for selected features only
feature_min_selected = feature_min[selected_indices]
feature_max_selected = feature_max[selected_indices]

print(f'Training shape: {X_train_fs.shape}')
print(f'Test shape: {X_test_fs.shape}')

# Retrain Decision Tree
print('\n1. Decision Tree...')
dt = DecisionTreeClassifier(random_state=0)
dt.fit(X_train_fs, y_train)
dt_score = dt.score(X_test_fs, y_test)
print(f'   Accuracy: {dt_score:.4f}')

dt_train = dt.predict(X_train_fs)
dt_test = dt.predict(X_test_fs)

# Retrain Random Forest
print('2. Random Forest...')
rf = RandomForestClassifier(random_state=0)
rf.fit(X_train_fs, y_train)
rf_score = rf.score(X_test_fs, y_test)
print(f'   Accuracy: {rf_score:.4f}')

rf_train = rf.predict(X_train_fs)
rf_test = rf.predict(X_test_fs)

# Retrain Extra Trees
print('3. Extra Trees...')
et = ExtraTreesClassifier(random_state=0)
et.fit(X_train_fs, y_train)
et_score = et.score(X_test_fs, y_test)
print(f'   Accuracy: {et_score:.4f}')

et_train = et.predict(X_train_fs)
et_test = et.predict(X_test_fs)

# Retrain XGBoost
print('4. XGBoost...')
xg = xgb.XGBClassifier(n_estimators=10, eval_metric='mlogloss')
xg.fit(X_train_fs, y_train)
xg_score = xg.score(X_test_fs, y_test)
print(f'   Accuracy: {xg_score:.4f}')

xg_train = xg.predict(X_train_fs)
xg_test = xg.predict(X_test_fs)

# =============================================================================
# 11. STACKING MODEL
# =============================================================================

print('\n' + '='*70)
print('TRAINING STACKING MODEL')
print('='*70)

dt_train = dt_train.reshape(-1, 1)
et_train = et_train.reshape(-1, 1)
rf_train = rf_train.reshape(-1, 1)
xg_train = xg_train.reshape(-1, 1)
dt_test = dt_test.reshape(-1, 1)
et_test = et_test.reshape(-1, 1)
rf_test = rf_test.reshape(-1, 1)
xg_test = xg_test.reshape(-1, 1)

x_train = np.concatenate((dt_train, et_train, rf_train, xg_train), axis=1)
x_test = np.concatenate((dt_test, et_test, rf_test, xg_test), axis=1)

stk = xgb.XGBClassifier(eval_metric='mlogloss').fit(x_train, y_train)

y_predict = stk.predict(x_test)
y_true = y_test
stk_score = accuracy_score(y_true, y_predict)

print(f'Stacking Accuracy: {stk_score:.4f}')
precision, recall, fscore, _ = precision_recall_fscore_support(
    y_true, y_predict, average='weighted'
)
print(f'Precision: {precision:.4f}')
print(f'Recall: {recall:.4f}')
print(f'F1-score: {fscore:.4f}')

print('\nClassification Report:')
print(classification_report(y_true, y_predict, target_names=labelencoder.classes_))

# =============================================================================
# 12. SAVE MODELS
# =============================================================================

print('\n' + '='*70)
print('SAVING MODELS')
print('='*70)

os.makedirs('models', exist_ok=True)

joblib.dump(dt, 'models/dt_model.pkl')
joblib.dump(rf, 'models/rf_model.pkl')
joblib.dump(et, 'models/et_model.pkl')
joblib.dump(xg, 'models/xg_model.pkl')
joblib.dump(stk, 'models/stk_model.pkl')
joblib.dump(labelencoder, 'models/label_encoder.pkl')
joblib.dump(selected_features, 'models/selected_features.pkl')
joblib.dump(feature_min_selected, 'models/feature_min.pkl')
joblib.dump(feature_max_selected, 'models/feature_max.pkl')

print('✓ dt_model.pkl')
print('✓ rf_model.pkl')
print('✓ et_model.pkl')
print('✓ xg_model.pkl')
print('✓ stk_model.pkl')
print('✓ label_encoder.pkl')
print('✓ selected_features.pkl')
print('✓ feature_min.pkl')
print('✓ feature_max.pkl')

print(f'\n✓ All models use {len(selected_features)} features')

# =============================================================================
# 13. CONFUSION MATRIX
# =============================================================================

plt.figure(figsize=(10, 8))
cm = confusion_matrix(y_true, y_predict)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=labelencoder.classes_,
            yticklabels=labelencoder.classes_)
plt.title('Confusion Matrix - Stacking Model')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=300)
print('\n✓ Confusion matrix saved: confusion_matrix.png')

print('\n' + '='*70)
print('TRAINING COMPLETE!')
print('='*70)
print(f'Models trained with {len(selected_features)} selected features')
print(f'Feature range preserved from original data')
print(f'Ready for IDPS deployment!')