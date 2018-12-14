
use strict;
use MIME::Base64 qw( encode_base64 decode_base64 );
use Digest::SHA  qw(sha1);
use Authen::PAM;

sub OS_authent {
  my ($username,$password) = @_;
  my $cr = 0;
  sub my_conv_func {
    my @res;
    while ( @_ ) {
        my $code = shift;
        my $msg = shift;
        my $ans = "";
        $ans = $password if ($code == PAM_PROMPT_ECHO_OFF() );
        push @res, (PAM_SUCCESS(),$password);
    }
    push @res, PAM_SUCCESS();
    return @res;
  }
  my $pamh;
  pam_start("passwd", $username, \&my_conv_func, $pamh);
  if ($pamh) {
    my $res = pam_authenticate($pamh);
    $cr=1 if ( $res == PAM_SUCCESS() );
  }
  pam_end($pamh);
  return $cr;
}

sub unauthorized {
    my $s = shift;
    my $infos = shift;
    my $header =  shift;
    if (! defined $infos->{"PARAMETER"}->{"TICKET_USER"}) {
      $infos->{"PARAMETER"}->{"TICKET_USER"} = "";
      $infos->{"PARAMETER"}->{"REMOTE_USER"} = "";
    }
    print $s get_header($infos,$header,{ "Content-Type"=>"text/html",
					 "WWW-Authenticate"=>"Basic realm=\"$localhost\" charset=\"UTF-8\"",
					 "HTTP_CR"=>"401 Unauthorized",
					 "COOKIES" => { "time" => time(),
							"REMOTE_USER"=>$infos->{"PARAMETER"}->{"REMOTE_USER"},
							"TICKET_USER"=>$infos->{"PARAMETER"}->{"TICKET_USER"} }
				       } );
    print $s $html_header."<h3>Bonjour chez vous !!</h3>".$html_footer;
}
sub authenticate {
  my $s = shift;
  my $infos = shift;
  my $header =  shift;
  my $cr = 0;

  if ( $infos->{"PARAMETER"}->{"TICKET_USER"} ne "" ) {
      ### verif validité du ticket quand il existe
      my ($p_time,$p_addr,$p_user,$p_agent) = split("£",decrypto($localhost.$infos->{"REMOTE_ADDR"}.$svrsalt, $infos->{"PARAMETER"}->{"TICKET_USER"} ));
      if ($p_addr  eq $infos->{"REMOTE_ADDR"} &&
          $p_user  eq $infos->{"PARAMETER"}->{"REMOTE_USER"} &&
	  $p_time + $authent_cache >= time() ) {
                $cr=1;
		#print $s get_header($infos,$header, { "Content-Type"=>"text/plain", "Location"=>$uri_dest, "HTTP_CR"=>"302 Found","COOKIES" => {} } );
		#&dump_all($s,\$infos,\$header);
      }
      else {
        $infos->{"PARAMETER"}->{"TICKET_USER"} = "";
        &unauthorized($s,$infos,$header);
      }
  }
  elsif (defined $header->{"Authorization"} ) {
    my ($username,@p) =  split(':', decode_base64(${\(split(/\s+/,$header->{"Authorization"}))[1]}) );
    my $password = join('',@p);
    undef @p;
    if (user_pass_is_good($username, $password) ) {
      $cr=1;
      $infos->{"PARAMETER"}->{"REMOTE_USER"}=$username;
      ## genere un ticket avec infos cryptées
      my $ticket = crypto($localhost.$infos->{"REMOTE_ADDR"}.$svrsalt, time()."£".$infos->{"REMOTE_ADDR"}."£".$username."£".$header->{"User-Agent"});
      print $s get_header($infos,$header, { "Content-Type"=>"text/plain", "Location"=>$infos->{"URI"}."?".$infos->{"PARAMETERS"}, "HTTP_CR"=>"302 Found",
					    "COOKIES" => { "REMOTE_USER" => $username, "TICKET_USER" => $ticket } });
    }
    else {
       &unauthorized($s,$infos,$header);
    }
  }
  else {
    &unauthorized($s,$infos,$header);
  }
  return $cr;
}
sub create_user {
  my $user = shift;
  my $pass = shift;
  my @alls=();
  open(my $f, "<", $user_file);
  while(<$f>) {
    chomp($_);
    my ($u,$h) = split(/:/,$_);
    if ($u ne $user) {
      push(@alls,$_);
    }
  }
  close($f);
  push(@alls,$user.":". crypt($pass,'$6$'.&get_salt(8)));
  open(my $f, ">", $user_file);
  foreach(@alls) {
    print $f $_."\n";
  }
  close($f);
}
sub user_pass_is_good {
    my $user=shift;
    my $pass=shift;
    my $good=0;
    my $hash = "";
    if ( -f $user_file ) {
      open(my $f, "<", $user_file);
      while(<$f>) {
        chomp($_);
        my ($u,$h) = split(/:/,$_);
        $hash = $h if ($u eq $user);
      }
      close($f);
    }
    if ($hash ne "" && $hash eq crypt($pass,$hash)) {
      $good=1;
    }
    else {
      $good = OS_authent($user,$pass);
    }
    return $good;
}
sub get_salt {
  my $len = shift;
  my $ret = "";
  my $str = 'abcdefghigklmnopqrstuvwxyz0123456789';
  for (my $i = 0; $i < $len; $i++) {
    if (int(rand(2)) == 1) { $ret .=    substr($str, int(rand(length($str))), 1); }
    else                   { $ret .= uc(substr($str, int(rand(length($str))), 1)); }
  }
  return $ret;
}

## crypto fonctions
###################
sub crypto {
  my $pcle=shift;
  my $txtin=shift;
  my $txtout="";
  my $sizetxt=length($txtin);
  
  my $sha1_text=sha1($txtin); # SHA1 du texte
  
  my $cle=GetRealKey($pcle,$sha1_text);
  #print $cle."\n";
  $txtout=$sha1_text; # Init le text avec le SHA1 du texte pour decrypto
  
  my @tcle=split(//,$cle);
  my $pos=0;
  my $icle=0;
  while($pos < $sizetxt) {
    my $asci_car = unpack('C',substr($txtin,$pos,1));
    my $asci_cle = unpack('C',$tcle[$icle]);
    my $val = ($asci_car - ( ($asci_cle + $pos)*($asci_cle - $pos) ) ) % 256;

    $val = $val ^ $asci_cle;
    $txtout .= pack('C',$val);
    
    #print "ICI-->$asci_car $asci_cle ".round_unite($asci_cle / 2)." $val ".chr($val)."<-\n";
    $pos++;
    $icle++;
    if ($icle > $#tcle) {
      $icle=0;
    }
  }
  return encode_base64($txtout);
}
sub decrypto {
  my $pcle=shift;
  my $txtin=decode_base64(shift);
  my $txtout=""; # Init le text de sortie
  my $sha1_text=substr($txtin,0,20); # recup SHA1 du texte
  $txtin = substr($txtin,20); # vire le SHA1 du debut du texte
  my $cle=GetRealKey($pcle,$sha1_text);
  #print $cle."\n";
  my $sizetxt=length($txtin);
  my @tcle=split(//,$cle);
  my $pos=0;
  my $icle=0;
  while($pos < $sizetxt) {
    my $asci_car = unpack('C',substr($txtin,$pos,1));
    my $asci_cle = unpack('C',$tcle[$icle]);
    $asci_car = $asci_car ^ $asci_cle;
    my $val = ($asci_car + ( ($asci_cle + $pos)*($asci_cle - $pos) ) ) % 256;

    $txtout .= pack('C',$val);
    
    #print "ICI-->$asci_car $asci_cle ".round_unite($asci_cle / 2)." $val ".chr($val)."<-\n";
    $pos++;
    $icle++;
    if ($icle > $#tcle) {
      $icle=0;
    }
  }
  return $txtout;
}
sub GetRealKey {
  my $pcle = shift;
  my $sha1txt = shift;
  my $resul="";
  my $max = length($pcle);
  my $i = 0;
  while ($i <= $max) {
     my $t=$i+20;
     my $piece;
     if($t<$max) {
       $piece=substr($pcle,$i,20);
     }
     else {
       $piece=substr($pcle,$i);
     }
     $piece = sha1($piece) ^ $sha1txt;
     $resul = $resul . $piece;
     $i = $i + 20;
  }
  return $resul;
}
return 1;

