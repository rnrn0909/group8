# SessionWebFingerprinting


### Task 3
- Collect network traces from previous work
- Extract TCP/TLS/Tor cell traces depending on user's choice
- Process extraction as dataset for further tasks
- Expand the toolbox
- Options for toolbox:
```
[VALID KEYWORD]
    pages : Collect pages from a randomly selected trend
    visit : Visit URLs collected in Firefox through TOR
    dictionary : Generate JSON mapping  of URL-hash for troubleshooting
    database : Loads the database with the selected countries for the experiment
    extraction : Extraction of data at different layers
    automatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction
    merging : Merging of already existing TCP/TLS/TOR  cell traces collected for a given URL in a single file
```

# Util
- [PyShark]
- [mysql.connector]
- [zipfile]


### Task 4
- Remove outlier traces from previous extraction
- Ask user to select the minimum number of valid traces
- If the number of valid traces is under selected minimum number, it calls crawling function and collects traces. (Task2 & Task 3)
- Remove detected outliers from all types of trace files
- Make user to select the method to detect outlier(3)
- Generate the feature of each trace(13)
- Expand the toolbox
```
[VALID KEYWORD]
    outlier : Detect and remove outliers
    feature : Extract features from traffic traces
```
# Util
- [pandas]
- [statistics]
- [numpy]
- [shutil]
- [scipy.stats]

