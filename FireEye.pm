# vim: filetype=perl sw=2 foldmethod=marker commentstring=\ #\ %s
package FireEye;
use Getopt::Long;
use Pod::Usage;
use Pod::Find qw(pod_where);


sub doc { # {{{
  my ($self,$doc) = @_;
  if (ref($doc)) {
    $self->{xml} = $doc;
  }
  $self->{xml};
} # }}}

sub new { # {{{
  my ($class,%self) = @_;
  return bless \%self,$class;
} # }}}

sub _simple_dump_unique { # {{{
  my ($self,$xpath) = @_;
  my $nodelist = $self->doc->findnodes($xpath);
  my %hash =  map { $_->toString(1) => 1 } $nodelist->get_nodelist;
  print map { "$_\n" } keys %hash;
} # }}}

sub _simple_dump { # {{{
  my ($self,$xpath) = @_;
  my $nodelist = $self->doc->findnodes($xpath);
  print map { $_->toString(1),"\n" } $nodelist->get_nodelist;
} # }}}

my $intersection = sub (\@\@) { # {{{
  my ($array_left,$array_right) = @_;
  my %hash_left = map { ($_,1) } @$array_left;
  grep { defined( $hash_left{$_} ) } @$array_right;
}; # }}}

=pod

=head1 COMMANDS

=cut

# COMMAND: xpath {{{

=head2 xpath

Search with a freeform XPath expression.

  xpath --expression="/xpath/node[criteria='selection']"

=cut

sub xpath {
  my ($self,@args) = @_;
  my $opts = {} ;
  my $ret = GetOptions($opts,"expression=s","event=s","value=s","help|?");
  if ($opts->{help} || !($opts->{expression} || $opts->{event})) { # {{{
    pod2usage(
      -msg=> "XPath Help ",
      -verbose => 99,
      -sections => [ qw(COMMANDS/xpath) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  my $xpath;
  if ($opts->{event}) {
    $xpath = sprintf("/procmon/eventlist/event[%s]%s",$opts->{event},$opts->{value})
  } else {
    $xpath = $opts->{expression};
  }

  $self->_simple_dump($xpath);
} # }}}

# COMMAND: alerts {{{

=head2 alerts

Display all alerts present in a file, displaying malware sample info and os change IDs

  alerts --alert 123456
  
=cut 
  
sub alerts {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","alert=i");

  my $xpath = '/FE:alerts/FE:alert';

  if ($opts->{alert}) {
    $xpath .= sprintf('[@id=%d]',$opts->{alert});
  }

  my $alerts = $self->doc->findnodes($xpath);

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "ALERTS help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/alerts) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  foreach my $alert ($alerts->get_nodelist) { # {{{

    my $alert_info;
    @$alert_info{qw(alert_id alert_url)} = map { $self->doc->findvalue($_,$alert) } qw(./@id ./FE:alert-url);
    print Data::Dumper->Dump([$alert_info],[qw($alert_info)]);

    my $malware;
    my ($malware_node) = $self->doc->findnodes("FE:explanation/FE:malware-detected/FE:malware",$alert);
    @$malware{qw(name type downloaded-at md5sum original executed-at application)} = map { $self->doc->findvalue($_,$malware_node) } qw(@name @type FE:downloaded-at FE:md5sum FE:original FE:executed-at FE:application);
    print Data::Dumper->Dump([$malware],[qw($malware)]);

    my $os_changes =  $self->doc->findnodes('./FE:explanation/FE:os-changes',$alert);
    foreach my $os_change ($os_changes->get_nodelist) { # {{{
      my $os_change_info;
      @$os_change_info{qw(id info version)} = map { $self->doc->findvalue($_,$os_change) } qw(./@id ./@osinfo ./@version);
      print Data::Dumper->Dump([$os_change_info],[qw($os_change_info)]);
    }  # }}}
  } # }}}

} # }}}

# COMMAND: processes {{{

=head2 processes

Display all processes in an alert, optionally filtered by oschange ID or lifecycle.

  processes --alert 123456 --oschange 12345432 --lifecycle=[started|terminated]
  
=cut 
  
sub processes {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","alert=i","oschange=i","lifecycle=s");

  my $xpath = '/FE:alerts/FE:alert';

  if ($opts->{alert}) {
    $xpath .= sprintf('[@id=%d]',$opts->{alert});
  }

  $xpath .= "/FE:explanation/FE:os-changes";

  if ($opts->{oschange}) {
    $xpath .= sprintf('[@id=%d]',$opts->{oschange});
  }

  $xpath .= "/FE:process";

  if ($opts->{lifecycle}) {
    $xpath .= sprintf('[@mode="%s"]',$opts->{lifecycle});
  }

  print STDERR "xpath = $xpath\n";
  my $processes = $self->doc->findnodes($xpath);

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "ALERTS help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/processes) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  foreach my $process ($processes->get_nodelist) { # {{{
    my $info;
    @$info{qw(executable pid ppid parentname cmdline ads mode filesize md5sum sha1sum)} = map { $self->doc->findvalue($_,$process) } qw(FE:value FE:pid FE:ppid FE:parentname FE:cmdline FE:fid @mode FE:filesize FE:md5sum FE:sha1sum);
    print $process->toString(1),"\n";
    #printf("PID:\t%s\nPPID:\t%s\nParent Image:\t%s\nImage File:\t%s\nCommand Line:\t%s\n",
    #print "Executable: $executable\n";
    #print $process->toString(1),"\n";
  } # }}}

} # }}}

# COMMAND: files {{{

=head2 files

Display file operations in an alert, optionally filtered by oschange ID, process ID, or file operation (mode).

  files --alert 123456 --oschange 12345432 --pid 1234 --mode=close
  
=cut 
  
sub files {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","alert=i","oschange=i","pid=i","mode=s");

  my $xpath = '/FE:alerts/FE:alert';

  if ($opts->{alert}) {
    $xpath .= sprintf('[@id=%d]',$opts->{alert});
  }

  $xpath .= "/FE:explanation/FE:os-changes";

  if ($opts->{oschange}) {
    $xpath .= sprintf('[@id=%d]',$opts->{oschange});
  }

  $xpath .= "/FE:file";

  my $expr;

  if ($opts->{mode}) {
    $expr .= ($expr?" and ":"") . sprintf('@mode = "%s"',$opts->{mode});
  }

  if ($opts->{pid}) {
    $expr .= ($expr?" and ":"") . sprintf('FE:processinfo/FE:pid/text() = %d',$opts->{pid});
  }

  $xpath .="[ $expr ]" if ($expr);

  print STDERR "xpath = $xpath\n";

  my $files = $self->doc->findnodes($xpath);

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "FILES help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/files) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  foreach my $file ($files->get_nodelist) { # {{{
    my $info;
    #@$info{qw(mode filename fid pid imagepath)} = map { $self->doc->findvalue($_,$file) } qw(@mode FE:value FE:fid FE:processinfo/FE:pid FE:processinfo/FE:imagepath);
    print $file->toString(1),"\n";
    #print Data::Dumper->Dump([$info],[qw($info)]);
  } # }}}

} # }}}

# COMMAND: regkey {{{

=head2 regkey

  regkey --alert 123456 --oschange 12345432 --pid 1234 --mode=[setval|added]
  
=cut 
  
sub regkey {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","alert=i","oschange=i","pid=i","mode=s");

  my $xpath = '/FE:alerts/FE:alert';

  if ($opts->{alert}) {
    $xpath .= sprintf('[@id=%d]',$opts->{alert});
  }

  $xpath .= "/FE:explanation/FE:os-changes";

  if ($opts->{oschange}) {
    $xpath .= sprintf('[@id=%d]',$opts->{oschange});
  }

  $xpath .= "/FE:regkey";

  my $expr;

  if ($opts->{mode}) {
    $expr .= ($expr?" and ":"") . sprintf('@mode = "%s"',$opts->{mode});
  }

  if ($opts->{pid}) {
    $expr .= ($expr?" and ":"") . sprintf('FE:processinfo/FE:pid/text() = %d',$opts->{pid});
  }

  $xpath .="[ $expr ]" if ($expr);

  print STDERR "xpath = $xpath\n";

  my $files = $self->doc->findnodes($xpath);

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "REGKEY help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/regkey) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  foreach my $file ($files->get_nodelist) { # {{{
    my $info;
    #@$info{qw(mode filename fid pid imagepath)} = map { $self->doc->findvalue($_,$file) } qw(@mode FE:value FE:fid FE:processinfo/FE:pid FE:processinfo/FE:imagepath);
    print $file->toString(1),"\n";
    #print Data::Dumper->Dump([$info],[qw($info)]);
  } # }}}

} # }}}

# COMMAND: maliciousalert {{{

=head2 maliciousalert

  maliciousalert --alert 123456 --oschange 12345432 --classtype=[setval|added]
  
=cut 
  
sub maliciousalert {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","alert=i","oschange=i","classtype=s");

  # malicious action
  # /FE:alerts/FE:alert[@id=59374991]/FE:explanation/FE:os-changes[@id=324788]/FE:malicious-alert/preceding-sibling::*[1]

  # description of malicious action
  # /FE:alerts/FE:alert[@id=59374991]/FE:explanation/FE:os-changes[@id=324788]/FE:malicious-alert

  my $xpath = '/FE:alerts/FE:alert';

  if ($opts->{alert}) {
    $xpath .= sprintf('[@id=%d]',$opts->{alert});
  }

  $xpath .= "/FE:explanation/FE:os-changes";

  if ($opts->{oschange}) {
    $xpath .= sprintf('[@id=%d]',$opts->{oschange});
  }

  $xpath .= "/FE:malicious-alert";

  my $expr;

  if ($opts->{classtype}) {
    $expr .= ($expr?" and ":"") . sprintf('@classtype = "%s"',$opts->{mode});
  }

  $xpath .="[ $expr ]" if ($expr);

  my $maliciousalerts = $self->doc->findnodes($xpath."|$xpath/preceding-sibling::*[1]");
  print STDERR "xpath = $xpath\n";

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "REGKEY help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/regkey) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  foreach my $maliciousalerts ($maliciousalerts->get_nodelist) { # {{{
    my $info;
    #@$info{qw(mode filename fid pid imagepath)} = map { $self->doc->findvalue($_,$file) } qw(@mode FE:value FE:fid FE:processinfo/FE:pid FE:processinfo/FE:imagepath);
    print $maliciousalerts->toString(1),"\n";
    #print Data::Dumper->Dump([$info],[qw($info)]);
  } # }}}

} # }}}

# processes = //FE:os-changes[@id=324699]/FE:process
# operations for a pid //FE:os-changes[@id=324699]//*[./FE:processinfo/FE:pid/text() = 2544]
