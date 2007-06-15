# BEGIN COPYRIGHT BLOCK
# This Program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; version 2 of the License.
# 
# This Program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307 USA.
# 
# In addition, as a special exception, Red Hat, Inc. gives You the additional
# right to link the code of this Program with code not covered under the GNU
# General Public License ("Non-GPL Code") and to distribute linked combinations
# including the two, subject to the limitations in this paragraph. Non-GPL Code
# permitted under this exception must only link to the code of this Program
# through those well defined interfaces identified in the file named EXCEPTION
# found in the source code files (the "Approved Interfaces"). The files of
# Non-GPL Code may instantiate templates or use macros or inline functions from
# the Approved Interfaces without causing the resulting work to be covered by
# the GNU General Public License. Only Red Hat, Inc. may make changes or
# additions to the list of Approved Interfaces. You must obey the GNU General
# Public License in all respects for all of the Program code and other code used
# in conjunction with the Program except the Non-GPL Code covered by this
# exception. If you modify this file, you may extend this exception to your
# version of the file, but you are not obligated to do so. If you do not wish to
# provide this exception without modification, you must delete this exception
# statement from your version and license this file solely under the GPL without
# exception. 
# 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK
#

package Util;

use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API; # Direct access to C API
use Mozilla::LDAP::LDIF;

require Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(portAvailable getAvailablePort isValidDN addSuffix getMappedEntries
                process_maptbl check_and_add_entry getMappedEntries);
@EXPORT_OK = qw(portAvailable getAvailablePort isValidDN addSuffix getMappedEntries
                process_maptbl check_and_add_entry getMappedEntries);

use strict;

use Socket;

# return true if the given port number is available, false otherwise
sub portAvailable {
    my $port = shift;
    my $proto = getprotobyname('tcp');
    my $rc = socket(SOCK, PF_INET, SOCK_STREAM, $proto);
    if ($rc == 1) {
        $rc = bind(SOCK, sockaddr_in($port, INADDR_ANY));
    }
    close(SOCK);
    return $rc and ($rc == 1);
}

# returns a randomly assigned port number, or -1
# if not able to find an available port
sub getAvailablePort {
    my $MINPORT = 1024;
    my $MAXPORT = 65535;

    srand( time() ^ ($$ + ($$ << 15)) );
    while (1) {
        my $port = $MINPORT + int(rand($MAXPORT-$MINPORT));

        if (portAvailable($port)) {
            return $port;
        }
    }
}

sub isValidDN {
    my $dn = shift;
    return ($dn =~ /^[0-9a-zA-Z_-]+=.*$/);
}

sub debug {
    print @_, "\n";
}

# delete the subtree starting from the passed entry
sub delete_all
{
	my ($conn, $bentry) = @_;
	my $sentry = $conn->search($bentry->{dn},
							   "subtree", "(objectclass=*)", 0, ("dn"));
	my @mystack = ();
	while ($sentry) {
		push @mystack, $sentry->getDN();
		$sentry = $conn->nextEntry();
	}
	# reverse order
	my $dn = pop @mystack;
	while ($dn) {
		$conn->delete($dn);
		my $rc = $conn->getErrorCode();
		if ( $rc != 0 ) {
			$conn->printError();
			print "ERROR: unable to delete entry $dn, error code: $rc\n";
			return 1;
		}
		$dn = pop @mystack;
	}
	return 0;
}

my %ignorelist = (
	"modifytimestamp", "modifyTimestamp",
	"createtimestamp", "createTimestamp",
	"installationtimestamp", "installationTimestamp",
	"creatorsname", "creatorsName",
	"modifiersname", "modifiersName",
	"numsubordinates", "numSubordinates"
);

my %speciallist = (
	"uniquemember", 1
);

# compare 2 entries
# return 0 if they match 100% (exception: %ignorelist).
# return 1 if they match except %speciallist.
# return -1 if they do not match.
sub comp_entries
{
	my ($e0, $e1) = @_;
	my $rc = 0;
	foreach my $akey ( keys %{$e0} )
	{
		next if ( $ignorelist{lc($akey)} );
		my $aval0 = $e0->{$akey};
		my $aval1 = $e1->{$akey};
		my $amin;
		my $amax;
		my $a0max = $#{$aval0};
		my $a1max = $#{$aval1};
		if ( $a0max != $a1max )
		{
			if ( $speciallist{lc($akey)} )
			{
				$rc = 1;
				if ( $a0max < $a1max )
				{
					$amin = $a0max;
					$amax = $a1max;
				}
				else
				{
					$amin = $a1max;
					$amax = $a0max;
				}
			}
			else
			{
				$rc = -1;
				return $rc;
			}
		}
		my @sval0 = sort { $a cmp $b } @{$aval0};
		my @sval1 = sort { $a cmp $b } @{$aval1};
		for ( my $i = 0; $i <= $amin; $i++ )
		{
			my $isspecial = -1;
			if ( $sval0[$i] ne $sval1[$i] )
			{
				if ( 0 > $isspecial )
				{
					$isspecial = $speciallist{lc($akey)};
				}
				if ( $isspecial )
				{
					$rc = 1;
				}
				else
				{
					$rc = -1;
					return $rc;
				}
			}
		}
	}
	return $rc;
}

# if the entry does not exist on the server, add the entry.
# otherwise, do nothing
# you can use this as the callback to getMappedEntries, so
# that for each entry in the ldif file being processed, you
# can call this subroutine to add or update the entry
# use like this:
# getMappedEntries($mapper, \@ldiffiles, \&check_and_add_entry,
#                  [$conn, $fresh, $verbose]);
# where $conn is a perldap Conn
# $fresh if true will update the entry if it exists
# $verbose prints out more info
sub check_and_add_entry
{
	my ($context, $aentry) = @_;
	my $conn = $context->[0];
	my $fresh = $context->[1];
	my $verbose = $context->[2];
	my $sentry = $conn->search($aentry->{dn}, "base", "(objectclass=*)");
	do
	{
		my $needtoadd = 1;
		my $needtomod = 0;
		my $rval = -1;
		if ( $sentry && !$fresh )
		{
			$rval = comp_entries( $sentry, $aentry );
		}
		if ( 0 == $rval && !$fresh )
		{
			# the identical entry exists on the configuration DS.
			# no need to add the entry.
			$needtoadd = 0;
			goto out;
		}
		elsif ( (1 == $rval) && !$fresh )
		{
			$needtoadd = 0;
			$needtomod = 1;
		}
		elsif ( $sentry && $sentry->{dn} )
		{
			# $fresh || $rval == -1
			# an entry having the same DN exists, but the attributes do not
			# match.  remove the entry and the subtree underneath.
			if ( $verbose )
			{
				print "Deleting an entry dn: $sentry->{dn} ...\n";
			}
			$rval = delete_all($conn, $sentry);
			if ( 0 != $rval )
			{
				return 0;
			}
		}

		if ( 1 == $needtoadd )
		{
			$conn->add($aentry);
			my $rc = $conn->getErrorCode();
			if ( $rc != 0 )
			{
				print "ERROR: adding an entry $aentry->{dn} failed, error code: $rc\n";
				print "[entry]\n";
				$aentry->printLDIF();
				$conn->close();
				return 0;
			}
#			if ( $verbose )
#			{
#				print "Entry $aentry->{dn} is added\n";
#			}
		}
		elsif ( 1 == $needtomod )	# $sentry exists
		{
			foreach my $attr ( keys %speciallist )
			{
				foreach my $nval ( @{$aentry->{$attr}} )
				{
					$sentry->addValue( $attr, $nval );
				}
			}
			$conn->update($sentry);
			my $rc = $conn->getErrorCode();
			if ( $rc != 0 )
			{
				print "ERROR: updating an entry $sentry->{dn} failed, error code: $rc\n";
				print "[entry]\n";
				$aentry->printLDIF();
				$conn->close();
				return 0;
			}
		}
		if ( $sentry )
		{
			$sentry = $conn->nextEntry();	# supposed to have no more entries
		}
	} until ( !$sentry );
out:
	return 1;
}

# the default callback used with getMappedEntries
# just adds the given entry to the given list
sub cbaddent {
    my $list = shift;
    my $ent = shift;
    push @{$list}, $ent;
    return 1;
}

# given a mapper and a list of LDIF files, produce a list of
# perldap Entry objects which have had their tokens subst-ed
# with values from the mapper
# An optional callback can be supplied.  Each entry will be
# given to this callback.  The callback should return a list
# of localizable errors.  If no callback is supplied, the
# entries will be returned in a list.
# Arguments:
#  mapper - a hash ref - the keys are the tokens to replace
#           and the values are the replacements
#  ldiffiles - an array ref - the list of LDIF files to
#           operate on
#  callback (optional) - a code ref - a ref to a subroutine
#           that will be called with each entry - see below
#  context (optional) - this will be passed as the first
#           argument to your given callback - see below
#  errs (optional) - an array ref - This is how errors
#           are returned to the caller - see below
# Callback:
#  The callback sub will be called for each entry after
#  the entry has been converted.  The callback will be
#  called with the given context as the first argument
#  and the Mozilla::LDAP::Entry as the second argument,
#  and an errs array ref as the third argument.  The
#  callback should return true to continue processing,
#  or false if a fatal error was encountered that should
#  abort processing of any further.
# Errors:
#  This function should return an array of errors in the
#  format described below, for use with Resource::getText().
#  If the callback returns any errors
# Return:
#  The return value is a list of entries.
# Example usage:
#  sub handle_entries {
#    my $context = shift;
#    my $entry = shift;
#    .... do something with entry ....
#    .... if $context is Mozilla::LDAP::Conn, $conn->add($entry); ...
#    .... report errors ....
#    if ($fatalerror) {
#      return 0;
#    } else {
#      return 1;
#    }
#  }
#  $mapper = {foo => 'bar', baz => 'biff'};
#  @ldiffiles = ('foo.ldif', 'bar.ldif', ..., 'biff.ldif');
#  $conn = new Mozilla::LDAP::Conn(...);
#  @entries = getMappedEntries($mapper, \@ldiffiles, \&handle_entries, $conn);
#  Note that this will return 0 entries since a callback was used.
#  The simpler example is this:
#  @entries = getMappedEntries($mapper, \@ldiffiles);
#  
sub getMappedEntries {
    my $mapper = shift;
    my $ldiffiles = shift;
    my $callback = shift || \&cbaddent; # default - just add entry to @entries
    my @entries = ();
    my $context = shift || \@entries;
    my $error;

    if (!ref($ldiffiles)) {
        $ldiffiles = [ $ldiffiles ];
    }

	foreach my $ldiffile (@{$ldiffiles}) {
		open(MYLDIF, "< $ldiffile") or die "Can't open $ldiffile : $!";
        my $in = new Mozilla::LDAP::LDIF(*MYLDIF);
        debug("Processing $ldiffile ...");
        ENTRY: while (my $entry = Mozilla::LDAP::LDIF::readOneEntry($in)) {
            # first, fix the DN
            my $dn = $entry->getDN();
            my $origdn = $dn;
            while ( $dn =~ /%([\w_-]+)%/ ) {
                if (exists($mapper->{$1})) {
                    $dn =~ s{%([\w_-]+)%}{$mapper->{$1}}ge;
                } else {
                    print "ERROR: \"$origdn\" mapped to \"$dn\".\n";
                    print "The LDIF file $ldiffile contains a token $1 for which there is no mapper.\n";
                    print "Please check $ldiffile and your mapper to make sure all tokens are handled correctly.\n";
                    $error = 1;
                    last ENTRY;
                }
            }
            $entry->setDN($dn);
            # next, fix all of the values in all of the attributes
            foreach my $attr (keys %{$entry}) {
                my @newvalues = ();
                foreach my $value ($entry->getValues($attr)) {
                    # Need to repeat to handle nested subst
                    my $origvalue = $value;
                    while ( $value =~ /%([\w_-]+)%/ ) {
                        if (exists($mapper->{$1})) {
                            $value =~ s{%([\w_-]+)%}{$mapper->{$1}}ge;
                        } else {
                            print "ERROR: \"$origvalue\" mapped to \"$value\".\n";
                            print "The LDIF file $ldiffile contains a token $1 for which there is no mapper.\n";
                            print "Please check $ldiffile and your mapper to make sure all tokens are handled correctly.\n";
                            $error = 1;
                            last ENTRY;
                        }
                    }
                    push @newvalues, $value;
                }
                $entry->setValues( $attr, @newvalues );
            }

            if (!&{$callback}($context, $entry)) {
                print "There was an error processing entry ", $entry->getDN(), "\n";
                print "Cannot continue processing entries.\n";
                $error = 1;
                last ENTRY;
            }                

        }
		close(MYLDIF);
        last if ($error); # do not process any more ldiffiles if an error occurred
	}

	return @entries;
}

# you should only use this function if you know for sure
# that the suffix and backend do not already exist
# use addSuffix instead
sub newSuffixAndBackend {
    my $context = shift;
    my $suffix = shift;
    my $bename = shift;
    my $nsuffix = normalizeDN($suffix);
    my @errs;

    my $dn = "cn=$bename, cn=ldbm database, cn=plugins, cn=config";
    my $entry = new Mozilla::LDAP::Entry();
    $entry->setDN($dn);
    $entry->setValues('objectclass', 'top', 'extensibleObject', 'nsBackendInstance');
    $entry->setValues('cn', $bename);
    $entry->setValues('nsslapd-suffix', $nsuffix);
    $context->add($entry);
    my $rc = $context->getErrorCode();
    if ($rc) {
        return ('error_creating_suffix_backend', $suffix, $bename, $context->getErrorString());
    }

    $entry = new Mozilla::LDAP::Entry();
    $dn = "cn=\"$nsuffix\", cn=mapping tree, cn=config";
    $entry->setDN($dn);
    $entry->setValues('objectclass', 'top', 'extensibleObject', 'nsMappingTree');
    $entry->setValues('cn', "\"$nsuffix\"");
    $entry->setValues('nsslapd-state', 'backend');
    $entry->setValues('nsslapd-backend', $bename);
    $context->add($entry);
    $rc = $context->getErrorCode();
    if ($rc) {
        return ('error_creating_suffix', $suffix, $context->getErrorString());
    }

    return ();
}

sub findbecb {
    my $entry = shift;
    my $attrs = shift;
    return $entry->hasValue('objectclass', $attrs->[0], 1) &&
        $entry->hasValue('cn', $attrs->[1], 1);
}

sub findBackend {
    my $context = shift;
    my $bename = shift;
    my $ent;
    if (ref($context) eq 'Mozilla::LDAP::Conn') {
        $ent = $context->search("cn=ldbm database,cn=plugins,cn=config", "one",
                                "(&(objectclass=nsBackendInstance)(cn=$bename)")
    } else {
        $ent = $context->search("cn=ldbm database,cn=plugins,cn=config", "one",
                                \&findbecb, ['nsBackendInstance', $bename])
    }
}

sub findsuffixcb {
    my $entry = shift;
    my $attrs = shift;
    return $entry->hasValue('cn', $attrs->[0], 1) ||
        $entry->hasValue('cn', $attrs->[1], 1);
}

sub findSuffix {
    my $context = shift;
    my $suffix = shift;
    my $nsuffix = normalizeDN($suffix);
    my $ent;
    if (ref($context) eq 'Mozilla::LDAP::Conn') {
        $ent = $context->search("cn=mapping tree,cn=config", "one",
                                "(|(cn=\"$suffix\")(cn=\"$nsuffix\"))");
    } else {
        $ent = $context->search("cn=mapping tree,cn=config", "one",
                                \&findsuffixcb, ["\"$suffix\"", "\"$nsuffix\""])
    }
}

sub getUniqueBackendName {
    my $context = shift;
    my $bename = "backend";
    my $index = 0;
    my $ent = findBackend($context, ($bename . $index));
    while ($ent) {
        ++$index;
        $ent = findBackend($context, ($bename . $index));
    }

    return $bename.$index;
}

sub addSuffix {
    my $context = shift; # Conn
    my $suffix = shift;
    my $bename = shift; # optional
    my $ent;

    if ($bename && ($ent = findBackend($context, $bename))) {
        return ('backend_already_exists', $bename, $ent->getDN());
    }

    if ($ent = findSuffix($context, $suffix)) {
        return ('suffix_already_exists', $suffix, $ent->getDN());
    }

    if (!$bename) {
        $bename = getUniqueBackendName($context);
    }

    my @errs = newSuffixAndBackend($context, $suffix, $bename);

    return @errs;
}

# process map table
# [map table sample]
# fqdn =	FullMachineName
# hostname =	`use Sys::Hostname; $returnvalue = hostname();`
# ds_console_jar ="%normbrand%-ds-%ds_version%.jar"
#
# * If the right-hand value is in ` (backquote), the value is eval'ed by perl.
#   The output should be stored in $returnvalue to pass to the internal hash.
# * If the right-hand value is in " (doublequote), the value is passed as is.
# * If the right-hand value is not in any quote, the value should be found
#   in either of the setup inf file (static) or the install inf file (dynamic).
# * Variables surrounded by @ (e.g., @admin_confdir@) are replaced with the 
#   system path at the compile time.
# * The right-hand value can contain variables surrounded by % (e.g., %asid%)
#   which refers the right-hand value (key) of this map file.
# The %token% tokens are replaced in getMappedEntries
sub process_maptbl
{
	my ($mapper, @infdata) = @_;

    if (defined($mapper->{""})) {
        $mapper = $mapper->{""}; # side effect of Inf with no sections
    }

    KEY: foreach my $key (keys %{$mapper})
    {
        my $value = $mapper->{$key};
        if ($value =~ /^\"/)
        {
            $value =~ tr/\"//d; # value is a regular double quoted string - remove quotes
            $mapper->{$key} = $value;
        }
        elsif ($value =~ /^\`/)
        {
            $value =~ tr/\`//d; # value is a perl expression to eval
            my $returnvalue; # set in eval expression
            eval $value;
            $mapper->{$key} = $returnvalue; # perl expression sets $returnvalue
        }
        else
        {
            # get the value from one of the Inf passed in
            my $infsection;
            foreach my $thisinf (@infdata)
            {
                foreach my $section0 (keys %{$thisinf})
                {
                    $infsection = $thisinf->{$section0};
                    next if (!ref($infsection));
                    if (defined($infsection->{$value}))
                    {
                        $mapper->{$key} = $infsection->{$value};
                        next KEY;
                    }
                }
            }
            if (!defined($infsection->{$value}))
            {
                print "ERROR: $value not found in the .inf files\n";
                return {};
            }
        }
    }
	return $mapper;
}

1;
