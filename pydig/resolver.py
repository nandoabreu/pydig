import re # to parse non +short queries
import random
import subprocess
import logging

from .query_type import QueryType

logger = logging.getLogger(__name__)


class Resolver:

    def __init__(
        self,
        executable='dig',
        nameservers=None,
        additional_args=None,
        encoding='utf-8',
        option=None, # option: 'query_time', but defaults to short (as in `dig +short domain`)
    ):
        """
        Stores some customisable options into this resolver instance
        """
        self.executable = executable
        self.nameservers = nameservers or []
        self.additional_args = additional_args or []
        self.encoding = encoding
        self.option = option or 'short'

    @property
    def nameserver(self):
        """
        Returns a random nameserver we should query against
        """
        return random.choice(self.nameservers)

    @staticmethod
    def _execute(args):
        """
        Calls out to subprocess with the passed in args

        This method is normally mocked in tests
        """
        logger.info('Executing subprocess.check_output({})'.format(repr(args)))  # pragma: no cover
        return subprocess.check_output(args)  # pragma: no cover

    def _args(self, domain, query_type):
        """
        Builds up the final arguments to pass into subprocess

        dig @1.1.1.1 example.com A +short
        """
        yield self.executable

        # Add in a random nameserver
        if self.nameservers:
            yield '@{}'.format(self.nameserver)

        # The record we want to query
        yield domain

        # Our query type
        yield query_type.name

        # We only care about the result, but some extra info may be provided
        if 'query_time' in self.option: pass
        else: yield '+short'

        # Add in any additional args
        yield from self.additional_args

    def query(self, domain, query_type):
        """
        Queries the resolver for a specific domain and query type

        Returns a list of records
        """
        domain = domain.lower()
        query_type = QueryType.get(query_type)

        args = list(self._args(domain, query_type))
        output = self._execute(args).decode(self.encoding).strip()

        res = []
        if output:
            if '+short' not in args:
                # Parse the response if not a +short query

                parsing = False
                for line in output.split('\n'):
                    if 'Query time' in line:
                        # Set query_time to this information

                        r = re.findall('.*Query time: (\d+) msec', line)
                        try: self.query_time = int(r[0])
                        except: self.query_time = None

                    elif 'ANSWER SECTION' in line:
                        # Start parsing after this line
                        parsing = True

                    elif parsing:
                        if re.match(f'^{domain}', line):
                            # Parse responses (IP address, NS)
                            r = re.findall(f'.*IN\t+{args[-1]}\t+(.*)$', line)
                            try: res.append(r[0])
                            except: pass

                        else:
                            # Stop parsing
                            parsing = False
            else:
                res = output.split('\n')

        return res

