#! /usr/bin/perl

use strict;
use warnings;
use Fcntl;
use IO::Socket;
use POSIX ":sys_wait_h";
use URI::Escape;
use File::MimeInfo qw {mimetype mimetype_isa};

use vars qw ( $ssl $document_root $disable_slash $user_file $html_header $html_footer $authent_cache $cache_maxage $nl $localhost $svrsalt );
$nl = "\x0d\x0a";

## Parametres & fonctions utilisateurs
## Services sont nommés: HTTPD_*
#######################################
chdir( dirname($0) );
require("HTTPD_function.pl");
if( $ssl ) {
  require IO::Socket::SSL;
  IO::Socket::SSL->import;
}

## Fonction server HTTP
########################
sub list_all_function {
  my @r = ();
  foreach my $entry ( keys %main:: ) {
    if (main->can($entry)) {
      if ($entry =~ /^HTTPD_(.*)/) {
        $entry = $1;
        push(@r,$entry) ;
      }
    }
  }
  return sort @r;
}

sub dirname {
  my @tmp = split(/\//,shift);
  pop @tmp;
  return join("/",@tmp);
}

sub format_dt {
  # Formatage de la date
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($_[0]);
  $year += 1900;
  $mon++;
  $mday = "0".$mday if (length($mday) == 1 );
  $mon = "0".$mon   if (length($mon)  == 1 );
  $hour = "0".$hour if (length($hour) == 1 );
  $min = "0".$min   if (length($min)  == 1 );
  $sec = "0".$sec   if (length($sec)  == 1 );
  return "$year-$mon-$mday-$hour:$min:$sec";
}

sub get_header {
    my $infos = shift;
    my $header_req = shift;
    my $response = shift || { "Content-Type"=>"text/html", "HTTP_CR"=>"200 OK" };

    my $content_type = $response->{"Content-Type"} || "text/html";
    delete $response->{"Content-Type"};
    my $http_cr = $response->{"HTTP_CR"} || "200 OK";
    delete $response->{"HTTP_CR"};
    my $cookies = $response->{"COOKIES"} || {};

    my $t=time();
    my @time=split(" ",gmtime($t)); $time[0] .= ",";
    my @expire_time=split(" ",gmtime($t+$cache_maxage)); $expire_time[0] .= ",";

    my $cook_str = "";
    while(my ($n,$v) = each %{$cookies}) {
      $cook_str .= "Set-Cookie: $n=".uri_escape($v)."; path=/; HttpOnly".$nl;
    }
    delete $response->{"COOKIES"};
    my $header_str = "";
    while(my ($n,$v) = each %{$response}) {
      $header_str .= $n.": ".$v.$nl;
    }
    return "HTTP/1.1 $http_cr${nl}Server: TroCon 1.0${nl}Connection: close${nl}".
	"Date: @{time} GMT${nl}".
	"Expires: @{expire_time} GMT${nl}".
	"Cache-Control: max-age=$cache_maxage${nl}".
	"Content-Type: ".$content_type.$nl.
        $header_str.$cook_str.$nl;
}


sub return_error {
  my $s = shift;
  my $infos = shift;
  my $header = shift;
  my $err = shift;
  my $message = shift || "";
  print $s get_header($infos,$header,{ "Content-Type"=>"text/html", "HTTP_CR"=>$err })."$html_header<h3>Pas beau !!</h3>HTTP ERROR $err<br>$message$html_footer";
}

sub parse_req {
    my $s = shift;
    my $buf = shift;
    my $header = shift;
    my $infos = shift;

    my @h = split(/$nl/,$buf);
    my $cmd = shift @h;
    return 0 if (! defined $cmd);
    # parse headers
    foreach (@h) {
       my @l = split(": ",$_);
       $header->{$l[0]}=$l[1];
    }
    # get infos
    my @cmd = split(/\s+/,$cmd);
    $infos->{"REMOTE_ADDR"}=$s->peerhost();
    $infos->{"REMOTE_PORT"}=$s->peerport();
    $infos->{"CMD"}=shift @cmd;
    $infos->{"PROTO"}= pop @cmd;
    $infos->{"PROTO"}="" if (! defined $infos->{"PROTO"});
    $cmd = join(' ',@cmd);
    $cmd =~ s/^\///;
    ($infos->{"URI"},$infos->{"PARAMETERS"})=split(/\?/,$cmd);
    $infos->{"PARAMETERS"}="" if (! defined $infos->{"PARAMETERS"});
    foreach(split('&', $infos->{"PARAMETERS"} ) ) {
      $_ =~ tr/+/ /;
      my @l = split(/=/, $_ );
      $infos->{"PARAMETER"}->{uri_unescape($l[0])} = uri_unescape($l[1]);
    }
    # 1er param de l'URI peut etre = nom d'une fonction
    $infos->{"URI"}="/" if (! defined $infos->{"URI"});
    ($infos->{"NAME"}) = split(/\//,$infos->{"URI"});
    $infos->{"NAME"} = "" if (! defined $infos->{"NAME"} );
    if(defined $header->{"Cookie"}) {
       foreach (split(/;/,$header->{"Cookie"})) {
          $_ =~ s/^\s+//;
          $_ =~ s/\s+$//;
          $_ =~ tr/+/ /;
          my @t = split(/=/,$_);
          $infos->{"PARAMETER"}->{uri_unescape($t[0])} = uri_unescape($t[1]);
       }
    }

    if ($ssl) {
      $infos->{"SSL_CIPHER"} = $s->get_cipher();
      eval "\$infos->{\"SSL_VERSION\"} = \$s->get_sslversion()";
    }
    return 1;
}

sub dump_all {
      my $s = shift;
      my $infos = shift;
      my $header = shift;
      # dump all infos
      print $s "## infos & headers".$nl;
      print $s "##################".$nl;
      foreach my $var ( ( $infos , $header ) ) {
        foreach(sort keys %{${$var}}) {
          if ($_ eq "PARAMETER") {
            while(my ($p,$v) = each %{${$var}->{$_}} ) {
              $v="" if (! defined $v);
              print $s "PARAMETER=>".$p." => ".$v.$nl;
            }
          }
          else {
            print $s $_." => ".${$var}->{$_}.$nl;
          }
          
        }
        print $s "##################".$nl;
      }
}

sub clean_child {
  my $all = shift;
  foreach(keys %{$all}) {
   delete $all->{$_} if ( waitpid($_, WNOHANG) );
  }
}

sub serve_a_page {
    my $s = shift;
    my $buf;
    #$s->recv($buf,1024);
    my $lenread=undef;
    do {
      my $tbuf;
      $lenread=$s->sysread($tbuf,1024);
      $buf .= $tbuf;
    }
    while($lenread == 1024);
    my $header= {};
    my $infos= {};
    if (! &parse_req($s,$buf,$header,$infos) ) {
      return_error($s,$infos,$header,"400 Bad Request");
    }
    elsif ( $infos->{"CMD"} eq "OPTIONS" ) {
        print $s get_header($infos,$header, { "Content-Type"=>"text/plain", "HTTP_CR"=>"200 OK", "Allow"=>"OPTIONS, GET" } );
    }
    elsif ( $infos->{"CMD"} ne "GET" && $infos->{"CMD"} ne "POST" ) {
        return_error($s,$infos,$header,"400 Bad Request");
    }
    elsif ($infos->{"NAME"} eq "") { # Cas racine
      if ($disable_slash) {
        return_error($s,$infos,$header,"403 Forbidden","Could not serve ..<br><b>Bonjour chez vous ...</b>".$nl);
      }
      else {
        # retour de perroquet :
        print $s get_header($infos,$header,
			{"Content-Type"=>"text/html", "HTTP_CR"=>"200 OK", "Header-DeM"=>"allo",
			 "COOKIES" => {  }
                        } ).$html_header;
        print $s "<h3>"."You said :</h3><pre>".$buf."</pre>".$nl;
        # Expose les repertoires et URI/API a utiliser
        print $s "<table align=\"center\" width=\"75%\" border=\"1\" cellspacng=\"0\" cellpadding=\"0\">";
        print $s "<tr><th>List of availables services</th><th>List of availables files &amp; directories</th></tr><tr><td>";
        foreach( &list_all_function() ) {
          print $s "<a href=\"/$_\">".$_."</a><br>\n";
        }
        print $s "</td><td>";
        if (-d $document_root) {
          opendir(my $dir, $document_root);
          foreach ( sort grep { !/^\./ && -f $document_root."/".$_ } readdir($dir) ) {
            print $s "<a href=\"/$_\">".$_."</a><br>\n";
          }
          rewinddir($dir);
          print $s "<hr>";
          foreach ( sort grep { !/^\./ && -d $document_root."/".$_ } readdir($dir) ) {
            print $s "<a href=\"/$_\">".$_."</a><br>\n";
          }
          closedir($dir);
        }
        print $s "</td></tr></table><pre>";
        # dump all infos
        &dump_all($s, \$infos, \$header);
        # &dump_all(*STDOUT, \$infos, \$header);
        print $s "</pre>".$html_footer;
      }
    }
    else { # cas pas racine
      if ( $infos->{"URI"} =~ /\.\./ ) {
        # verif de l'URI = interdiction d'un .. dans l'URI !!!
        return_error($s,$infos,$header,"403 Forbidden","Could not serve ..<br><b>Bonjour chez vous ...</b>".$nl);
      }
      elsif ( -f $document_root."/".$infos->{"URI"} ) {
        # serve a simple file
        print $s get_header($infos,$header, {"Content-Type"=>mimetype($infos->{"URI"}), "HTTP_CR"=>"200 OK" } );
        open(my $fh , "<", $document_root."/".$infos->{"URI"});
        while(<$fh>) {
          print $s $_;
        }
        close $fh;
      }
      elsif ( -d $document_root."/".$infos->{"URI"} ) {
        # serve a directory
        print $s get_header($infos,$header);
        opendir(DIR,$document_root."/".$infos->{"URI"}); 
        my @files = grep { !/^\./ } readdir(DIR);
        closedir(DIR);
        print $s "$html_header<h3>Listing of /".$infos->{"URI"}."</h3>";
        print $s "<a href=\"/".dirname($infos->{"URI"})."\">Parent Directory</a><br><br>".$nl;
        foreach(@files) {
          print $s "<a href=\"/".$infos->{"URI"}."/$_\">".$_."</a><br>".$nl;
        }
        print $s $html_footer.$nl;
      }
      else {
        # cas on cherche la fonction
        # get a handle sur la fonction
        my $sub = main->can("HTTPD_".$infos->{"NAME"});
        if ($sub) {
          my $auth = main->can("authenticate");
          if ( $auth ) {
            $sub->($s,$infos,$header) if ($auth->($s,$infos,$header));
          }
          else {
            $sub->($s,$infos,$header);
          }
        }
        else {
          return_error($s,$infos,$header,"404 Not Found")
        }
      }
    }
    $s->close();
    $s->shutdown($s);
    # log activity
    print format_dt(time()) ." ". $infos->{"REMOTE_ADDR"}." ".$infos->{"PARAMETER"}->{"REMOTE_USER"};
    print " ".$infos->{"CMD"}." ".$infos->{"URI"}. " ".$infos->{"PARAMETERS"}."\n";
}

sub server_die {
  print format_dt(time())."Outta here! SIG@_ received.";
  die " pid $$ bye\n";
}
sub start_server {
  $SIG{INT} = \&server_die;
  $SIG{TERM} = \&server_die;
  my $port = shift;
  my $pid=fork();
  if (! (defined $pid && $pid == 0)) {
    ## Ici le pere !!
    print "Starting server ...\n";
    sleep 1;
    return 1;
  }
  ## Ici on est dans le fils
  ## IE le process master du serveur
  $localhost = `hostname`;
  chomp($localhost);
  if (! defined($port) || $port eq "") {
    $port = 8080;
  }
  else {
    my @tmp = split(':',$port);
    if ($#tmp > 0) {
      $localhost=$tmp[0];
      $port=$tmp[1];
    }
  }
  print "listen on $localhost:$port\nlogfile is server.log\n";
  ## ouverture log et redirect stdout et STDERR vers le log 
  open(my $flog, '>>', 'server.log');
  select($flog); $|=1;
  *STDERR = $flog;
  ## Ouverture de la socket d'ecoute. ##
  my $listener;
  if ($ssl) {
    if ( ! -f "server.key" && ! -f "server.crt" ) {
       `openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=$localhost/O=AutoSigned httpd trocon/C=FR"`;
       chmod 0600, "server.key";
    }
    $listener = IO::Socket::SSL->new(LocalAddr => $localhost ,LocalPort => $port, Listen => 5, ReuseAddr => 1, SSL_cert_file => 'server.crt', SSL_key_file => 'server.key',);
  }
  else {
    $listener = IO::Socket::INET->new(LocalAddr => $localhost ,LocalPort => $port, Listen => 5, ReuseAddr => 1);
  }
  if (! defined $listener) {
    die "Erreur can't bind $localhost:$port $!\n";
  }
  open(my $fpid,">","trocon.pid");
  print $fpid $$;
  close($fpid);
  undef $fpid;
  $svrsalt=int(rand($$)+1)+time();
  if (my $s = main->can("sha1")) {
    $svrsalt = $s->($svrsalt);
  }
  if(main->can("authenticate")) {
    if ( ! -f $user_file || ! -s $user_file ) {
        my $pass = &get_salt(8);
        print "create default user= web:$pass\n";
        &create_user("web",$pass);
        chmod 0600, $user_file;
    }
  }
  print format_dt(time())." serveur launched $$ listen on $localhost:$port\n";
  my $childs = {};
  while (1) {
    my $s = $listener->accept;
    if ( defined $s ) {
      my $pid=fork();
      if (defined $pid && $pid == 0) {
        ## Ici le fils !!
        # print "\nbegin of pid $$".$nl; sub END { print "end of pid $$".$nl; }
        open(my $flog, '>>', 'server_child.log');
        select($flog); $|=1;
        *STDERR = $flog;
        &serve_a_page($s);
        ## sort apres le service de la page
        exit;
      }
      $childs->{$pid} = 1;
      &clean_child($childs);
    }
  }
  $listener->close;
  print "Fin\n";
}

## MAIN
#######
my $action=shift || "";
if ($action =~ /^stop$|^shutdown$/i) {
  if (-f "trocon.pid") {
    open(my $fpid,"<","trocon.pid");
    my $pid2kill = <$fpid>;
    close($fpid);
    print "kill $pid2kill\n";
    kill INT => $pid2kill;
    unlink("trocon.pid");
  }
  else {
    print "No server (file trocon.pid not exists.\n";
  }
}
elsif ($action =~ /^start$/i) {
  my $port=shift || "";
  start_server($port);
}
elsif ($action =~ /^usermod$/i) {
  create_user(shift,shift);
}
else {
  print "Usage:".$nl;
  print "\t$0 start <addr>:<port>".$nl;
  print "\t$0 <stop|shutdown>".$nl;
  print "\t$0 <usermod> <username> <userpass> ## add or modify user password".$nl;
}

