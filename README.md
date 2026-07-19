# 🔍 goz - Find your files on Windows instantly

[![](https://img.shields.io/badge/Download-goz-blue.svg)](https://github.com/indigestible-ice204/goz/releases)

Goz acts as a high-speed search engine for your computer. It reads the master file table of your hard drive to provide results as you type. This tool gives you an alternative to built-in search functions that feel slow or clunky. It works on Windows systems using NTFS drives.

## 🚀 Getting Started

Follow these steps to set up the software on your machine:

1. Visit the [releases page](https://github.com/indigestible-ice204/goz/releases) to download the software.
2. Select the file named goz.exe for your version of Windows.
3. Save the file to your desktop or a folder of your choice.
4. Double-click the file to open the interface.

The application requires no installation. You may move the file to any folder to keep your machine organized.

## ⚙️ System Requirements

Goz runs on any modern version of Windows that uses the NTFS file system. You need at least 50 MB of disk space to cache search indexes. The program uses minimal memory during operation to ensure your computer stays fast. It does not require administrative rights for basic searches, though some deep index functions benefit from these permissions.

## 🛠 How to Use

Once you open the software, a simple window appears. Type your search terms in the box at the top. The program updates the list of files below the box in real time. 

You can filter results by typing file extensions. For example, typing .jpg shows only image files. Use the settings menu to choose which drives the program scans. You can also hide system folders to keep your search results clean.

## ⚡ Performance Benefits

Standard Windows search tools often index every file in real time, which consumes computer resources. Goz reads the USN journal and the MFT directly. These internal Windows logs contain a map of every file location on your disk. Because the application reads this map instead of scanning each folder, it shows your files the moment your fingers hit the keys.

## 🛡 Security and Privacy

This program runs locally on your computer. It does not send your file names or search history to any server. No tracking code exists inside the application. Your data stays on your hard drive. 

## ❓ Frequently Asked Questions

**Does the program slow down my computer?**
No. It consumes a small amount of memory and idles when you stop typing.

**Can I search across multiple drives?**
Yes. You can add secondary and external hard drives to the scan list in the settings menu.

**What happens if I move a file?**
The program updates its index automatically. You will see the new location of the file after the next refresh cycle.

**Is it safe for work computers?**
The tool requires no installation and leaves no traces in the system registry, making it a portable choice for office environments.

**Why does the search window look empty?**
The program needs a moment to index your drives on the first run. Wait a few seconds for the status bar to show that the index is complete.

## 📌 Usage Tips

* Press the forward slash / key to jump to the search box quickly.
* Right-click any file in the results list to open its location in File Explorer.
* Use the menu to toggle case-sensitive searching if you need to find specific file names.
* Keep the application open in the background to ensure your search index stays current.

Keywords: cli, everything, everything-search, file-search, filesystem, mft, ntfs, rust, search-engine, usn-journal, windows