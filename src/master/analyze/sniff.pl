#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use List::Util qw(sum);
use Socket qw(inet_pton AF_INET AF_INET6);
use Net::Whois::IP qw(whoisip_query);

# First connect to the database
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

{
	# We want to know what IP addresses are out of the line. We count how many different IP addresses there are for each batch and set a limit on how small count of IP addresses can be based on that.
	my $ip_hist = $dbh->selectall_hashref('SELECT COUNT(*) AS cnt, request, ip, batch, MIN(host) AS host FROM pings JOIN ping_requests ON ping_requests.id = request WHERE ip IS NOT NULL GROUP BY request, ip, batch', [qw(request batch ip)]);
	# Due to the whoisip_query getting stuck sometimes, disconnect from the DB for the time being.
	$dbh->rollback;
	$dbh->disconnect;

	my %reports;

	for my $request (sort { $a <=> $b } keys %$ip_hist) {
		my $req_data = $ip_hist->{$request};
		my $any = [values %{[values %$req_data]->[0]}]->[0];
		for my $batch (sort keys %$req_data) {
			my $batch_data = $req_data->{$batch};
			my (%cnt, %ip_cnt, %limit);
			# We keep separate counts and limits for each family. Otherwise, the few odd clients that are IPv6-only will just always stand out.
			while (my ($ip, $record) = each %$batch_data) {
				for my $family (AF_INET, AF_INET6) {
					if (inet_pton($family, $ip)) {
						$record->{family} = $family;
						$cnt{$family} += $record->{cnt};
						$ip_cnt{$family} ++;
					}
				}
			}
			$limit{$_} = $cnt{$_} / ($ip_cnt{$_} ** 2) for keys %cnt;
			while (my ($ip, $record) = each %$batch_data) {
				if ($record->{cnt} < $limit{$record->{family}}) {
					push @{$reports{$any->{host}}->{$ip}}, {
						limit => $limit{$record->{family}},
						count => $record->{cnt},
						batch => $batch,
						family => $record->{family},
					};
				}
			}
		}
	}

	undef $ip_hist;

	my %whitelists = (
		'^AKAMAI-(\d+|PA|ARIN-\d+)$' => 'Akamai',
		'^AIBV$' => 'Akamai',
		'^AKAMAI$' => 'Akamai',
		'^EU-AKAMAI-\d+$' => 'Akamai',
		'^TWITTER-NETWORK$' => 'Twitter',
		'^GOOGLE$' => 'Google',
		'^MICROSOFT$' => 'Microsoft',
		'^MSFT-GFS$' => 'Microsoft',
		'^MSFT$' => 'Microsoft',
		'^MICROSOFT-1BLK' => 'Microsoft',
		'^EBAY-\d+$' => 'Ebay',
		'^IE-TWITTER-INTL-' => 'Twitter',
		'^SEZNAM-CZ$' => 'Seznam',
		'^FIO-BANKA-NET$' => 'FIO',
		'^(ATL1|LAX1|SJC1|SEA1)$' => 'Facebook',
		'^FACEBOOK-INC$' => 'Facebook',
		'^TFBNET\d+$' => 'Facebook',
		'^IAD1$' => 'Facebook',
	);

	my $count = keys %reports;
	$SIG{ALRM} = sub { die "WHOIS timeout\n" };
	alarm 120 * $count; # Two minutes for each woisip_query should be enough. Hopefully that's enough and hopefully SIGALRM is able to kill the syscall.

	for my $host (sort keys %reports) {
		print "Minority IP addresses on $host:\n";
		my $ips = $reports{$host};
		my %whitelist_ips;
		IP:
		while (my ($ip, $details) = each %$ips) {
			my $whois = whoisip_query($ip);
			my %whois = map { lc $_ => $whois->{$_} } keys %$whois;
			my $netname = $whois{netname};
			for my $rex (keys %whitelists) {
				if ($netname =~ /$rex/) {
					$whitelist_ips{$whitelists{$rex}} ++;
					next IP;
				}
			}
			print "• $ip\n";
			print "  hostname: " . gethostbyaddr(inet_pton($details->[0]->{family}, $ip), $details->[0]->{family}) . "\n";
			print "  owner: '$netname'\n";
			print "  batches: " . (join ', ', map "$_->{batch}($_->{count})", @$details) . "\n";
		}
		if (%whitelist_ips) {
			print "• Whitelisted owners: " . (join ', ', map "$_($whitelist_ips{$_})", keys %whitelist_ips) . "\n";
		}
	}
	alarm 0;
}

my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

{
	# Extract weak ciphers and protocols
	my $ciph = $dbh->selectall_arrayref('SELECT request, batch, cipher, proto, COUNT(*) AS count, MIN(host) AS host, MIN(port) AS port FROM certs JOIN cert_requests on request = cert_requests.id GROUP BY request, batch, cipher, proto');

	my %weak_ciphs;
	my %weak_proto;

	my %strong_proto = (
		TLSv1 => 1,
		'TLSv1.1' => 1,
		'TLSv1.2' => 1,
	);

	my %strong_ciph = (
		AES128 => 1,
		AES256 => 1,
		AES384 => 1,
	);

	my %strong_sig = (
		SHA => 1,
		SHA256 => 1,
		SHA384 => 1,
	);

	for my $crecord (@$ciph) {
		my ($request, $batch, $cipher, $proto, $count, $host, $port) = @$crecord;
		if (!$strong_proto{$proto}) {
			push @{$weak_proto{$proto}}, $crecord;
		}
		my $orig_cipher = $cipher;
		my $fs = ($cipher =~ s/^(ECDHE|DHE)-//) ? $1 : undef;
		my $asym = ($cipher =~ s/^(ECDSA|DSA|RSA)-//) ? $1 : undef;
		$cipher =~ s/^(DES-CBC3|[^-]+)-//;
		my $ciph = $1;
		my $chain = ($cipher =~ s/^(GCM)-//) ? $1 : undef;
		my $sig = ($cipher =~ s/^(SHA\d*|MD5)$//) ? $1 : undef;
		if (length $cipher) {
			warn "Badly parsed cipher string, unparsed rest = $cipher for $host:$port ($count clients at $batch)\n";
			next;
		}
		if (!$strong_ciph{$ciph} || !$strong_sig{$sig}) {
			push @{$weak_ciphs{$orig_cipher}}, $crecord;
		}
	}

	undef $ciph;

	sub ciph_hosts($) {
		my ($records) = @_;
		my %hosts;
		for my $record (@$records) {
			my ($request, $batch, $cipher, $proto, $count, $host, $port) = @$record;
			push @{$hosts{"$host:$port"}}, "$batch ‒ $count";
		}
		print map "  ◦ $_\n", sort keys %hosts;
		# TODO: Do we want some more info?
	}

	if (%weak_proto) {
		print "Weak protocols:\n";
		for my $proto (sort keys %weak_proto) {
			print "• $proto\n";
			ciph_hosts $weak_proto{$proto};
		}
	}

	if (%weak_ciphs) {
		print "Weak ciphers:\n";
		for my $ciph (sort keys %weak_ciphs) {
			print "• $ciph\n";
			ciph_hosts $weak_ciphs{$ciph};
		}
	}
}

{
	# Detect when a certificate is different than in previous batch
	my $cert_history = $dbh->selectall_arrayref('SELECT MAX(host) AS host, MAX(port) AS port, batch, request, value, MAX(expiry) AS expiry, MAX(name) AS name, count(*) AS count FROM cert_chains JOIN certs ON certs.id = cert_chains.cert JOIN cert_requests ON certs.request = cert_requests.id WHERE ord = 0 GROUP BY request, batch, value ORDER by request, batch, value');

	my ($last_request, $last_batch, $prev_batch);
	my (%certs, %last_certs);
	my ($last_host, $last_port);
	my %report;
	my ($host, $port, $batch, $request, $value, $expiry, $name, $count);
	my $cmp_batches = sub {
		#print Dumper \%certs, \%last_certs, $last_batch, $prev_batch;
		return unless $last_batch && $prev_batch; # We are interested only if we have two batches to compare
		my %add = %certs;
		delete @add{keys %last_certs};
		my %remove = %last_certs;
		delete @remove{keys %certs};
		push @{$report{"$host:$port"}}, {
			prev => $prev_batch,
			curr => $last_batch,
			add => \%add,
			remove => \%remove,
		} if %add || %remove;
	};
	for my $record (@$cert_history) {
		($host, $port, $batch, $request, $value, $expiry, $name, $count) = @$record;
		if ($last_request != $request) {
			$cmp_batches->();
			undef $last_batch;
			undef $prev_batch;
			%certs = ();
			%last_certs = ();
			$last_request = $request;
			$last_host = $host;
			$last_port = $port;
		}
		if ($last_batch ne $batch) {
			$cmp_batches->();
			$prev_batch = $last_batch;
			$last_batch = $batch;
			%last_certs = %certs;
			%certs = ();
		}
		$certs{$value} = {
			expiry => $expiry,
			name => $name,
			count => $count,
		};
	}
	$cmp_batches->();

	undef $cert_history;

	next unless %report;
	print "Changed certificates\n";
	for my $host (sort keys %report) {
		print "$host:\n";
		for my $change (@{$report{$host}}) {
			print "• $change->{prev} → $change->{curr}\n";
			print map "  + $_ ($change->{add}->{$_}->{expiry}, $change->{add}->{$_}->{count} x)\n", sort keys %{$change->{add}};
			print map "  - $_ ($change->{remove}->{$_}->{expiry}, $change->{remove}->{$_}->{count} x)\n", sort keys %{$change->{remove}};
		}
	}
}

{
	# Certificates that don't match the desired name (MITM?)
	my $stm = $dbh->prepare('SELECT cert_chains.name, cert_requests.host, cert_requests.port, certs.batch, clients.name AS client, cert_chains.value, certs.request FROM cert_chains JOIN certs on certs.id = cert_chains.cert JOIN cert_requests ON cert_requests.id = certs.request JOIN clients ON clients.id = certs.client WHERE ord = 0');
	$stm->execute;
	my %report;
	while (my ($name, $host, $port, $batch, $client, $value, $request) = $stm->fetchrow_array) {
		my @names = split /\n/, $name;
		my $match;
		for my $n (@names) {
			my $host = $host;
			$host =~ s/\.$//;
			$n =~ s/\.$//;
			while ($n =~ s/^\*\.//) {
				$host =~ s/^.*?\.//;
			}
			if (lc $n eq lc $host) {
				$match = 1;
				last;
			}
		}
		if (@names > 1) {
			$name = "$names[0] and " . (scalar @names - 1) . " others";
		}
		push @{$report{$request}->{$value}}, {
			name => $name,
			host => $host,
			port => $port,
			client => $client,
			batch => $batch,
		} unless $match;
	}

	next unless %report;

	print "Certificates not matching name\n";
	while (my ($request, $certs) = each %report) {
		while (my ($value, $data) = each %$certs) {
			print "• $data->[0]->{host}:$data->[0]->{port} not matching $data->[0]->{name} ($value):\n";
			my %clients;
			for my $record (@$data) {
				push @{$clients{$record->{client}}}, $record->{batch};
			}
			for my $client (sort keys %clients) {
				print "  ◦ $client: ", (join ", ", @{$clients{$client}}), "\n";
			}
		}
	}
}

# Having multiple different ciphers or protocols for single host is strange. Even if it is multiple IP addresses with multiple certificates, the configuration is likely to be the same.
sub report_multi($) {
	my ($column) = @_;

	my $tree = $dbh->selectall_hashref("SELECT host, port, $column, COUNT(distinct client) AS cnt FROM certs JOIN cert_requests ON certs.request = cert_requests.id GROUP BY host, port, $column", [qw(host port), $column]);
	my $caption;
	for my $host (sort keys %$tree) {
		for my $port (sort { $a <=> $b } keys %{$tree->{$host}}) {
			my $values = $tree->{$host}->{$port};
			if (keys %$values > 1) {
				print "Multiple $column values:\n" unless $caption;
				$caption = 1;
				print "• $host:$port: ", (join ", ", map "$_($values->{$_}->{cnt})", sort keys %$values), "\n";
			}
		}
	}
}
report_multi 'cipher';
report_multi 'proto';
