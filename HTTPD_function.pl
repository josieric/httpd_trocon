############################
## Parametres utilsateurs
## inclus dans le serveur (...)
############################
use strict;

$ENV{"LC_ALL"}="POSIX";
$ssl=1; ## SSL or not=0
$document_root="htdocs";
$disable_slash=0; # service "perroquet" sur l'URI /
#$disable_slash=1; # Pas de service de l'URI /
$user_file="passwd.sha";
$authent_cache=3600; # Durée max en seconde de la session 
require("authenticate.pl"); ## Turn On Authenticate basic mechanism

$html_header="<!doctype html>$nl<html><body>";
$html_footer="</body></html>$nl";
#$cache_maxage=3600;
$cache_maxage=0;

############################
## Service authent
############################
use MIME::Base64 qw( encode_base64 decode_base64 );
sub HTTPD_login {
  my $s = shift;
  my $infos = shift;
  my $header =  shift;
  if (! defined $infos->{"PARAMETER"}->{"fromurl"}) {
    return_error($s,$infos,$header,"403 Forbidden","Could not serve ..".$nl);
  }
  else {
    my $fromurl=$infos->{"PARAMETER"}->{"fromurl"};
    $fromurl=decode_base64($fromurl) if ($fromurl !~ /^http/ );
    my $passphrase = &get_passphrase($fromurl);
    if ( defined $passphrase ) {
      my $cmd = "echo \"USERNAME=".$infos->{"PARAMETER"}->{"REMOTE_USER"}."&time=\"\`date '+%s-%Y-%m-%d-%H-%M-%S'\`\"&\"".rand();
      $cmd .= " | openssl enc -e -aes-256-cbc -a -salt  -k ".$passphrase;
      my $ticket=`$cmd`;
      chomp($ticket);
      print $s get_header($infos,$header,
			{"Content-Type"=>"text/plain", "Location"=>$fromurl."?ticket=".uri_escape($ticket),"HTTP_CR"=>"302 Found",
                         "COOKIES" => { "time" => time(),"ticket" => uri_escape($ticket)}} ).$ticket.$nl;
      #print $s `echo "$ticket" | openssl enc -d -aes-256-cbc -a -salt  -k $passphrase`;
    }
    else {
      return_error($s,$infos,$header,"400 Bad Request");
    }
  }
}
sub get_passphrase {
  my $service=shift;
  my @allservices=('https://houdini:8080');
  return "PassPhrasePartagéeParAppliProjet";
}

############################
## Fonctions utilsateurs
## incluses dans le serveur (...)
############################

sub HTTPD_hello_world {
  my $s = shift;
  my $infos = shift;
  my $header =  shift;
  print $s get_header($infos,$header)."$html_header<body><h3>Hello world</h3>$html_footer";
}

## Exemple d'un service annoncant un simple df
##############################################
sub HTTPD_df {
  my $s = shift;
  my $infos = shift;
  my $header =  shift;
  print $s get_header($infos,$header,{ "Content-Type"=>"text/html; charset=utf-8" }).$html_header;
  print $s "<pre>".` df -h`."</pre>";
  print $s $html_footer;
}

## meme styme avec pidstat
# mais en pipe (IE sans l'ensemble du resultat en mémoire)
# et en tableau HTML
###############################################################
sub HTTPD_pidstat_html {
  my $s = shift;
  my $infos = shift;
  my $header =  shift;
  print $s get_header($infos,$header,{ "Content-Type"=>"text/html; charset=utf-8" }).$html_header;
  open(my $cmd, "pidstat ".$infos->{"PARAMETER"}->{"option"}." 2>&1 |");
  print $s '<table>';
  <$cmd>;<$cmd>;
  while(<$cmd>) {
    my @d = split(/\s+/,$_);
    print $s '<tr><td>'.join('</td><td>',@d).'</td></tr>';
  }
  print $s '</table>';
  close($cmd);
  print $s $html_footer;
}

## SAR Graph
############
require("stat_host.pl");

sub HTTPD_sar_data {
  my $s = shift;
  my $infos = shift;
  my $header = shift;
  my ($file);
  print $s get_header($infos,$header, { "Content-Type"=>"text/plain" });
    if(! defined($infos->{"PARAMETER"}->{"type"})) {
      $infos->{"PARAMETER"}->{"type"} = "cpu";
    }
    my $sar_rep="/var/log/sa";
    $sar_rep = "/var/log/sysstat" if ( ! -d  $sar_rep );
    &get_sar_data($s,$infos->{"PARAMETER"}->{"type"},$sar_rep,$infos->{"PARAMETER"}->{"file"});
}
sub HTTPD_sar_graph {
  my $s = shift;
  my $infos = shift;
  my $header = shift;
  my ($file, $gtype);
  print $s get_header($infos,$header);
  print $s qq (<!DOCTYPE HTML>
  <html>
  <head>
  <script type="text/javascript" src="/dygraph/dygraph.min.js"></script>
  <link rel="stylesheet" src="/dygraph/dygraph.css" />
  <style type="text/css">
    .dygraph-label {
        /* This applies to the title, x-axis label and y-axis label */
        font-family: Arial, Helvetica, Helvetica;
     }
    .dygraph-legend { text-align: right ; margin: 20px; background: transparent; }
    .dygraph-title {
        /* This rule only applies to the chart title */
        font-size: 24px;
        text-align: center;
        color: gray;
        text-shadow: black 2px 2px 2px;
     }
     .migraph {
        border: 0px solid black;
        border-color: gray;
        border-width: 1;
        margin: 0px;
        padding: 0px;
        width: 85%;
        height:500px;
      }
  </style>
  <script type="text/javascript">
  function get_data() {
  res = );
  if($infos->{"PARAMETER"}->{"type"} =~ /^ram$|^swap$/) {
      $gtype="stacked";
  }
  else {
      $gtype="lines";
  }
  if(! defined($infos->{"PARAMETER"}->{"type"})) {
    $infos->{"PARAMETER"}->{"type"}="cpu";
  }

  my $sar_rep="/var/log/sa";
  $sar_rep = "/var/log/sysstat" if ( ! -d  $sar_rep );
  &get_sar_data($s,$infos->{"PARAMETER"}->{"type"},$sar_rep,$infos->{"PARAMETER"}->{"file"});
  print $s qq( return res;
  }
  function graph_stacked(divid,title) {
    var g2 = new Dygraph(
  	document.getElementById(divid),
           get_data(),
  	{
                  axes : {
                    y : {
  		    drawGrid: true,
  		    gridLineWidth: 0.5
  		  }
                  },
  		title: title,
  		legend: 'always',
  		connectSeparatedPoints: true,
  		//drawGapEdgePoints: true,
  		showRangeSelector: true,
  		highlightCircleSize: 5, // taille des points
        fillGraph: true,
        stackedGraph: true
  //      rollPeriod: 7,
  //      showRoller: true
  	});
  }
  function graph_line(divid,title) {
    new Dygraph(
  	document.getElementById(divid),
           get_data(),
  	{
                  axes: {
                    y : {
  		    drawGrid: true,
  		    gridLineWidth: 0.5
  		  },
                  },
  	highlightSeriesOpts: {
            strokeWidth: 2,
            strokeBorderWidth: 1,
            highlightCircleSize: 5,
          },
          highlightSeriesBackgroundAlpha: 1,
  	connectSeparatedPoints: true,
          strokeBorderWidth: 1,
  	title: title,
  	legend: 'always',
  	showRangeSelector: true
  	});
  }
  </script>
  </head>
  <body>
  <div align="center">
  <a href="/">Menu g&eacute;n&eacute;ral</a>&nbsp;&nbsp;<a href="javascript:history.back();">Retour</a>
  <form method="GET">);
  my @ALLTYPE=("cpu","ram","swap","io","inet");
  my @AFFTYPE=("CPU","RAM","SWAP","I/O","Net IPV4");
  print $s "Type : <select name=\"type\">";
  my $i=0;
  foreach my $the_type ( @ALLTYPE ) {
    print $s "<option value=\"".$the_type."\"";
    if ($infos->{"PARAMETER"}->{"type"} eq $the_type) { print $s " SELECTED"; }
    print $s ">".$AFFTYPE[$i]."</option>";
    $i++;
  }
  print $s "</select> &nbsp;&nbsp; ";
  print $s "File: <input title=\"Pour avoir toutes les dates: /var/log/[sa|syslog]/sa*\" name=\"file\" value=\"".$infos->{"PARAMETER"}->{"file"}."\"> &nbsp;&nbsp; ";
  print $s "<input type=\"submit\" value=\"Ok\">";
  print $s "</form> <div class=\"migraph\" id=\"graph\"></div>";
  print $s "<a href=\"javascript:graph_stacked('graph','".$infos->{"PARAMETER"}->{"type"}."')\">Stacked Graph</a>&nbsp;";
  print $s "<a href=\"javascript:graph_line('graph','".$infos->{"PARAMETER"}->{"type"}."')\">Graph Line</a>&nbsp;&nbsp;&nbsp;&nbsp;";
  print $s "<a href=\"/sar_data?type=".$infos->{"PARAMETER"}->{"type"}."&file=".$infos->{"PARAMETER"}->{"file"}."\">View data</a>";
  if ($gtype eq "stacked") {
    print $s "<script>graph_stacked('graph','".$infos->{"PARAMETER"}->{"type"}." $localhost');</script>";
  }
  else {
    print $s "<script>graph_line('graph','".$infos->{"PARAMETER"}->{"type"}." $localhost');</script>";
  }
  print $s "<pre>";

  opendir(my $dh, $sar_rep);
  # sort by mtime (9eme de stat)
  my @files = sort { ${\(stat($sar_rep."/".$b))[9]} <=> ${\(stat($sar_rep."/".$a))[9]}  }  grep { -f $sar_rep."/".$_ } readdir($dh);
  closedir($dh);
  foreach(@files) {
    if ( $_ !~ /^sar[0-9]*/ ) {
      print $s scalar(localtime(${\(stat($sar_rep."/".$_))[9]}))." ".(${\(stat($sar_rep."/".$_))[7]}/1024)." Ko <a href=\"?type=".$infos->{"PARAMETER"}->{"type"}."&file=$_\">$_</a>\n";
    }
  }
  print $s "</pre>\n</div>\n</body>\n</html>\n";
}


