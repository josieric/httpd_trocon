#! /usr/bin/perl

sub header_cpu {
  my $s = shift;
  print $s "\"dt,\%cputotal,\%iowait\\n\" +\n";
}
sub sar_cpu {
  my $s = shift;
  my $mifile=shift;

  my $NR=1;
  my $MIDATE="";
  open(my $c , "sar $mifile |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if    ($NR == 1) { my @t=split(/\//,$d[3]); $MIDATE = ($t[2]+2000)."-".$t[0]."-".$t[1]; }
    elsif ($NR == 3) {  }
    elsif ($d[0] =~ /^\d\d:\d\d:\d\d$/ && $_ !~ /LINUX RESTART/ && $d[1] ne "CPU" ) {
       print $s "\"".$MIDATE." ".$d[0].",". (100 - $d[7]) .",".$d[5]."\\n\" +\n";
    }
    $NR++;
  }
  close($c);
}

sub header_ram {
  my $s = shift;
  print $s "\"dt,MBfree,MBused\\n\" +\n";
}
sub sar_ram {
  my $s = shift;
  my $mifile=shift;

  my $NR=1;
  my $MIDATE="";
  open(my $c , "sar -r $mifile |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if    ($NR == 1) { my @t=split(/\//,$d[3]); $MIDATE = ($t[2]+2000)."-".$t[0]."-".$t[1]; }
    elsif ($NR == 3) {  }
    elsif ($d[0] =~ /^\d\d:\d\d:\d\d$/ && $_ !~ /LINUX RESTART/ && $d[1] ne "kbmemfree" ) {
       print $s "\"".$MIDATE." ".$d[0].",". ($d[1]/1024) .",".($d[2]/1024)."\\n\" +\n";
    }
    $NR++;
  }
  close($c);
}

sub header_io {
  my $s = shift;
  print $s "\"dt,blk_r/s,blk_w/s\\n\" +\n";
}
sub sar_io() {
  my $s = shift;
  my $mifile=shift;
  my $NR=1;
  my $MIDATE="";
  open(my $c , "sar -b $mifile |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if    ($NR == 1) { my @t=split(/\//,$d[3]); $MIDATE = ($t[2]+2000)."-".$t[0]."-".$t[1]; }
    elsif ($NR == 3) {  }
    elsif ($d[0] =~ /^\d\d:\d\d:\d\d$/ && $_ !~ /LINUX RESTART/ && $d[1] ne "tps" ) {
       print $s "\"".$MIDATE." ".$d[0].",". $d[4] .",".$d[3]."\\n\" +\n";
    }
    $NR++;
  }
  close($c);
}

sub header_swap {
  my $s = shift;
  print $s "\"dt,MBfree,MBused\\n\" +\n";
}
sub sar_swap {
  my $s = shift;
  my $mifile=shift;

  my $NR=1;
  my $MIDATE="";
  open(my $c , "sar -S $mifile |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if    ($NR == 1) { my @t=split(/\//,$d[3]); $MIDATE = ($t[2]+2000)."-".$t[0]."-".$t[1]; }
    elsif ($NR == 3) {  }
    elsif ($d[0] =~ /^\d\d:\d\d:\d\d$/ && $_ !~ /LINUX RESTART/ && $d[1] ne "kbswpfree" ) {
       print $s "\"".$MIDATE." ".$d[0].",". ($d[1]/1024) .",".($d[2]/1024)."\\n\" +\n";
    }
    $NR++;
  }
  close($c);
}

sub header_inet {
  my $s = shift;
  open(my $c , "export PATH=\$PATH:/usr/sbin:/sbin ; ip -f inet -o addr |");
  print $s "\"dt";
  while(<$c>) {
    if (!/127\.0\.0\.1/) {
      my @tmp=split(/\s+/, $_);
      print $s ",".$tmp[1].".rxkB/s,".$tmp[1].".txkB/s";
    }
  }
  print $s "\\n\" +\n";
  close($c);
}
sub sar_inet {
  my $s = shift;
  my $mifile=shift;
  my $inet_cond="";
  my $inet_max=0;
  my $pipe="";
  my $NR=1;
  open(my $c , "export PATH=\$PATH:/usr/sbin:/sbin ; ip -f inet -o addr |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if ( !/127\.0\.0\.1/ ) {
      $inet_cond .= $pipe."^".$d[1];
      $pipe="\|";
      $inet_max++;
    }
  }
  close($c);
  my $NR=1;
  my $MIDATE="";
  my $nb=0;
  open(my $c , "sar -n DEV $mifile |");
  while(<$c>) {
    chomp($_);
    my @d=split(/\s+/, $_);
    if    ($NR == 1) { my @t=split(/\//,$d[3]); $MIDATE = ($t[2]+2000)."-".$t[0]."-".$t[1]; }
    elsif ($d[1] =~ /$inet_cond/ && $d[0] =~ /^\d\d:\d\d:\d\d$/ && $_ !~ /LINUX RESTART/ && $d[1] ne "IFACE" ) {
       $nb++;
       print $s "\"".$MIDATE." ".$d[0] if ($nb == 1);
       print $s ",".$d[4].",".$d[5];
       if ($nb >= $inet_max) {
         print $s "\\n\" +\n";
         $nb=0;
       }
    }
    $NR++;
  }
  print $s "\\n\" +\n" if ($inet_max > 1);
  close($c);
}

sub relist_file {
  my $sar_rep=shift;
  my $f = shift;
  my @ret = ();
  if (-f $sar_rep."/".$f ) {
    push(@ret,$f);
    if ($#_ >= 0) {
      foreach(@_) {
        push(@ret,$_);
      }
    }
  }
  else {
     opendir(my $dh, $sar_rep);
     @ret = grep { -f $sar_rep."/".$_ && !/^sar[0-9]/ && /$f/} readdir($dh);
     closedir($dh);
  }
  return sort { ${\(stat($sar_rep."/".$a))[9]} <=> ${\(stat($sar_rep."/".$b))[9]}  } @ret;
}

sub get_sar_data {
  my $s=shift;
  my $type=shift;
  my $sar_rep=shift;
  my @list=relist_file($sar_rep,split(/\s+/,shift));

  if ( $#list == -1 ) {
    push(@list,"NOWTODAY");
  }

  eval "&header_$type(\$s)";
  foreach(@list) {
    my $mifile=" -f $sar_rep/".$_;
    $mifile="" if ($_ eq "NOWTODAY");
    eval "&sar_$type(\$s,\$mifile)";
  }
  print $s "\"\";\n";
}

#unshift(@ARGV,*STDOUT);
#get_sar_data(@ARGV);
return 1;


