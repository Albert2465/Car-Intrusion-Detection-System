import pandas as pd
import numpy as np
import joblib
import os
import glob

# 1. Configuration
DATA_PATH = r"C:\Users\aksha\Documents\projects\project_sapience\CNN-LSTM\test\data_cicids"
OUTPUT_FILE = "selected_data_export.csv"

def generate_selected_csv(path):
    # Load all available data files (Parquet or CSV)
    files = glob.glob(os.path.join(path, "*.parquet")) + glob.glob(os.path.join(path, "*.csv"))
    if not files:
        print("No data files found.")
        return

    dfs = [pd.read_parquet(f) if f.endswith('.parquet') else pd.read_csv(f) for f in files]
    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.strip() # Clean column names

    # 2. Cleaning (Matches your IDPS logic)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # 3. Load your pre-selected features
    try:
        selected_features = joblib.load('models/selected_features.pkl')
        print(f"Using {len(selected_features)} features from models/selected_features.pkl")
    except:
        # Fallback to high-impact defaults if .pkl is missing
        selected_features = ['Bwd Packet Length Std', 'Destination Port', 'Flow Duration', 'Label']
        print("Warning: selected_features.pkl not found. Using default list.")

    # 4. Balanced Sampling (Prevents file being too large)
    # We take a representative sample of each class
    df_selected = df.groupby('Label').apply(
        lambda x: x.sample(n=min(len(x), 10000), random_state=42)
    ).reset_index(drop=True)

    # 5. Filter for selected features + Label
    columns_to_keep = [f for f in selected_features if f in df_selected.columns]
    if 'Label' not in columns_to_keep:
        columns_to_keep.append('Label')
        
    final_df = df_selected[columns_to_keep]

    # 6. Save to CSV
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"✓ Success! Selected data saved to: {OUTPUT_FILE}")
    print(f"Final shape: {final_df.shape}")

if __name__ == "__main__":
    generate_selected_csv(DATA_PATH)