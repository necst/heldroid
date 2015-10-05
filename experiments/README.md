# heldroid_associator.py
Lo script `heldroid_associator.py` permette di associare i report provenienti da VirusTotal con i dati provenienti da HelDroid, creando un oggetto JSON e scrivendolo in un file di testo. Attualmente è richiesto che il file .csv ottenuto da HelDroid contenga nella prima colonna il percorso del file APK esaminato, e che quest'ultimo abbia come nome il proprio hash, seguito dall'estensione ".apk".Ad esempio: /home/nicola/Desktop/apk/72e9f2ca12a1794ad716d0f28c6cfbf1b0bbfb2725d55fcef96ce3fd0931d163.apk

 - Un esempio di uso è:

        $ python heldroid_associator.py intelligencefiles/ransomware -o result.txt

 - Help message:

        $ python heldroid_associator.py -h
        usage: heldroid_associator.py [-h] [-r] [-o <file_name>]
                                      [folders [folders ...]]
        
        This program lets you download VT reports and associate them with heldoid .csv
        output file. In particular it searches all hashes from the .csv file, performs
        a request to VT and outputs a .txt file. IMPORTANT: It is assumed that the APK
        file name corresponds to its SHA or MD5 hash, i.e. <SHA|MD5>.apk
        
        positional arguments:
          folders               A list of .csv files to examine or a list of folders
                                in which the CSV file(s) should be searched. See also
                                option "-r".
        
        optional arguments:
          -h, --help            show this help message and exit
          -r, --recursive       Perform a recursive search in <folders>
          -o <file_name>, --output <file_name>
                                Name of the output file (the ".txt" extension will be
                                added, if not present)  
