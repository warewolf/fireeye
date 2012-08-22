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
  xpath --event="/xpath/node[criteria='selection']" --value="xpath"

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

# COMMAND: pids {{{

=head2 pids

Display all pids present in a log file.

  pids

=cut

sub pids {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","report=i");

  my $xpath = '/FE:alerts/FE:alert/FE:explanation/FE:os-changes';
  if ($opts->{report}) {
    $xpath .= sprintf('[@id=%d]',$opts->{report});
  }
  my $nodelist = $self->doc->findnodes($xpath);

  if ($opts->{help}) { # {{{
    pod2usage(
      -msg => "PIDS help",
      -verbose => 99,
      -sections => [ qw(COMMANDS/pids) ],
      -exitval=>0,
      -input => pod_where({-inc => 1}, __PACKAGE__),
    );
  } # }}}

  my $pids;
  foreach my $node ($nodelist->get_nodelist) {
    foreach my $value_node ($self->doc->findnodes('.//FE:pid',$node)) {
      my $value = $value_node->to_literal();
      $pids->{$value}++;
    }
  }
  print join(" ", keys %{$pids}),"\n";
} # }}}

# COMMAND: alerts {{{

=head2 alerts

Display all alerts present in a file

  pids
  
=cut 
  
sub alerts {
  my ($self,@args) = @_;

  my $opts = {} ;
  my $ret = GetOptions($opts,"help|?","report=i");

  my $xpath = '/FE:alerts/FE:alert';
  if ($opts->{report}) {
    $xpath .= sprintf('[@id=%d]',$opts->{report});
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

  foreach my $alert ($alerts->get_nodelist) {
    my ($id,$alert_url) = map { $self->doc->findvalue($_,$alert) } qw(./@id ./FE:alert-url);
    print "Id: $id\n";
    print "URL: $alert_url\n";
    
  }

} # }}}

# processes = //FE:os-changes[@id=324699]/FE:process
# operations for a pid //FE:os-changes[@id=324699]//*[./FE:processinfo/FE:pid/text() = 2544]
