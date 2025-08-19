# email_phishing_using_AgenticAI

python analyze_email.py /path/to/email_or_folder output.csv

# optional: extract attachments to a folder
python analyze_email.py /path/to/emls output.csv --extract-attachments /path/to/out_attachments

##If need to run the benchmarking CLI
python analyze_email.py ./emails results.csv
# labels file has columns: file_path,label
python analyze_email_benchmark.py ./emails results.csv --evaluate labels.csv
python analyze_email_benchmark.py ./emails results.csv --evaluate labels.csv --eval-output preds.csv
python analyze_email_benchmark.py ./emails results.csv --evaluate labels.csv --grid-step 1
    

 -------------------------------- 
    Verdict thresholds (why 40 / 70?)

    They’re engineering defaults to make triage useful out-of-the-box:
        ≥70 → “Malicious”, 40–69 → “Suspicious”, <40 → “Benign.”
            These are starting points, not gospel. Different mail streams (B2B vs. consumer) will require different cutoffs. 
            Industry reports also show the current threat mix skews heavily to URL-based phishing, which is why links weigh meaningfully.
    How to benchmark & tune (recommended)::
        https://huggingface.co/datasets/zefang-liu/phishing-email-dataset
        https://phishtank.org/


