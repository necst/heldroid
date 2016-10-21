# HelDroid
HelDroid is a tool that we started developing in 2014 to deal with the analysis
of Android ransomware. What it does in a nutshell is find clues in the
disassembled Android bytecode that indicate the presence of code used to
implement the typical features of ransomware. This includes:

* use of encryption routines without user intervention
* locking the screen and make the device "unusable"
* displaying threatening messages on the screen to ask for a ransom
* abuse of the Device Admin API for unattended locking or wiping

It does not deal with native code, mostly because native code is binary code,
for which there are [other great tools](http://angr.io) that we don't want to
re-invent. We focus on the routines that are tied to the abuse of the Android
API for implementing ransomware. Remember, our approach is almost 100% static
program analysis, that is, we don't run the sample unless necessary. On the one
hand this makes things simpler, on the other hand, we don't deal with
dynamically expressed ransomware behavior.

There are several details behind this curtain, most of which are described in
two academic papers and one conference presentation (Blackhat EU 2016, London):

```
@InProceedings{   andronio_heldroid_2015,
  shorttitle    = {HelDroid},
  author        = {Andronio, Niccolò and Zanero, Stefano and Maggi, Federico},
  title         = {{HelDroid}: Dissecting and Detecting Mobile Ransomware},
  booktitle     = {International {{Symposium}} on {{Research}} in {{Attacks}},
                  {{Intrusions}} and {{Defenses}} ({{RAID}})},
  volume        = {9404},
  series        = {Lecture Notes in Computer Science},
  pages         = {382--404},
  location      = {Kyoto, Japan},
  doi           = {10.1007/978-3-319-26362-5_18},
  date          = {2015-10},
  note          = {https://github.com/phretor/publications/raw/master/files/papers/conference-papers/andronio_heldroid_2015.pdf}
}

@InProceedings{   zheng_greateatlon_2016,
  shorttitle    = {GreatEatlon},
  author        = {Zheng, Chenghyu and Della Rocca, Nicola and Andronio,
                  Niccolò and Zanero, Stefano and Maggi Federico},
  title         = {GreatEatlon: Fast, Static Detection of Mobile Ransomware},
  location      = {Guangzhou, People's Republic of China},
  date          = {2016-10-10},
  note          = {https://github.com/phretor/publications/raw/master/files/papers/conference-papers/zheng_greateatlon_2016.pdf}
}

@Unpublished{     maggi_greateatlonbheu_talk_2016,
  shorttitle    = {GreatEatlonBHEU},
  author        = {Maggi, Federico and Zanero, Stefano},
  title         = {{Pocket-sized Badness: Why Ransomware Comes as a Plot Twist
                  in the Cat-Mouse Game}},
  eventtitle    = {{Blackhat Europe}},
  location      = {London, UK},
  url           = {https://www.blackhat.com/eu-16/briefings.html},
  date          = {2016-11-03},
  howpublished  = {Peer-reviewed Talk},
  note          = {https://github.com/phretor/publications/raw/master/files/talks/maggi_greateatlonbheu_talk_2016.pdf}
}
```

## Requirements
HelDroid requires:

* Java 1.7+
* [Gradle 3.1+](https://docs.gradle.org/current/userguide/installation.html)

## Install
HelDroid is written in Java, and has a few dependencies. We strive to keep the
`lib/` subdir as small as possible, putting all deps into the `build.gradle`
file. Unfortunately, some of the deps that we need are "prototype" libraries
(so to speak) or poorly distributed JARs for which no repository exists.

## Run
Without furter ado:
```
$ git clone https://github.com/necst/heldroid
$ cd heldroid/
$ gradle build
$ gradle shadowJar
$ mkdir -p test/apks
$ curl http://detect.ransom.mobi/fetch-apk?family=slocker&hash=d721a38e55441e3273754fa642f2744567dc786df356e89fa0bfa3cfd63ad0ed > \
  test/apks/d721a38e55441e3273754fa642f2744567dc786df356e89fa0bfa3cfd63ad0ed.apk
$ java -jar build/libs/heldroid-all.jar \
  detector                              \
  scan                                  \
  test/apks/2fcd8c40e3b59786a2661054bcc2ee4124a80aee737035f59995a943b29302fd.apk \
  test/output.csv                       \
  test/
```

This in turn will create:

* `examined.txt` in the current directory, holding a cache of scanned file paths
* `diagnostics.csv` in the current directory, holding a bunch of stats
* `test/2fcd8c40e3b59786a2661054bcc2ee4124a80aee737035f59995a943b29302fd.json` holding detailed info about the analysis

```
{
  "lockDetected": true,
  "lockStrategy": "DrawOver",
  "textDetected": true,
  "textScore": 1,
  "languages": [
    "english"
  ],
  "hasRWPermission": true,
  "encryptionDetected": false,
  "photoCaptureDetected": false,
  "deviceAdminUsed": true,
  "deviceAdminPolicies": "[USES_ENCRYPTED_STORAGE]",
  "fromReflection": false,
  "textComment": "Threat: 1.000000, Porn: 1.000000, Law: 0.732520, Copyright: 0.348155, Moneypak: 0.894427",
  "suspiciousFiles": "{
		copyright = [res/values/strings.xml, assets/home.html],
		law = [res/values/strings.xml, assets/home.html],
		moneypak=[res/values/strings.xml, assets/home.html],
		threat=[res/values/strings.xml, assets/home.html],
		porn=[res/values/strings.xml, assets/home.html]}"
}
```

# The Command Line Interface, Explained

```
$ java -jar build/libs/heldroid-all.jar   # call the JVM
  <mode of operation>                     # what to do: detection or pre-filter
  <operation>
  <sample.apk>                            # has to have an *.apk extension
  <output.csv>                            # write results
  <working directory>                     # where to write <sample.json>
```

For more details, try this:
```
$ java -jar build/libs/heldroid-all.jar
bin/heldroid (filter|detector) [options]
options depend on the command invoked
```

```
$ java -jar build/libs/heldroid-all.jar filter
java -jar build/libs/heldroid-all.jar filter source features-file [-s] [-g] [-c model attributes]
source:
   an apk file, a directory containing an unpacked apk file,
   a .apklist text file containing a line-by-line list of absolute apk paths
   or a directory (which will be recursively searched for any of the above)
features-file:
   a csv file containing extracted features, and possibly a prediction
   if -c is enabled
-s: silent mode
   Only classifications and critical exceptions are written in output
-g: google play mode
   Also downloads meta-data from google play store as features
-c: classification mode
   model is a valid weka model file and attributes an data-empty arff file that
   specifies attributes used by the model. Only features whose name is included in
   the attribute list are mined
-server: server mode
   starts a classification http server that receives an apk file as an octet-stream
   in a multipart/form-data POST request and returns a json response containing features
   and class probabilities. Route to use is /scan. To pass an hash, perform a GET request
   to route /hash passing 'hash' as query parameter
```

```
$ java -jar build/libs/heldroid-all.jar detector
java -jar build/libs/heldroid-all.jar detector (server|scan|pcap|learn) [[args]]

    server <conf_dir> <watch_folder>:
       Scan any new APK file popping up in the <watch_folder> and spin up a webserver
       The <conf_dir> must contain:
         - AndroidCallbacks.txt
         - Conditions.txt
         - EasyTaintWrapperSource.txt
         - SourcesAndSinks.txt

    scan <conf_dir> <directory> <output.csv> <json_result_directory>:
       Scan all *.apk in directory (recursively). Save JSON data in <json_result_directory>.
       The <conf_dir> must contain:
         - AndroidCallbacks.txt
         - Conditions.txt
         - EasyTaintWrapperSource.txt
         - SourcesAndSinks.txt

    pcap <directory>:
       Analyzes network-dump.pcap in the second-level subdirectories of the specified directory

    learn <lang> <textfile>:
       learns a sentence detector model for language lang analyzing sentences
       from the given text file, one per line
```

# To Document
How to se the PCAP utilities. Old doc says: use `jnetpcap-linux.jar` on Linux
platforms and `jnetpcap.jar` on Windows platforms, but it's not clear how to
Gradle-ize this.

# People
* Nicolò Andronio, architect and first developer (MSc Thesis, Politecnico di Milano and UIC)
* Nicola Della Rocca, second developer (MSc Thesis, Politecnico di Milano)
* Stefano Zanero, advisor
* Federico Maggi, main advisor and maintainer

# Feedback
Feedback is always welcome. Please open an issue if you have any ;-)
