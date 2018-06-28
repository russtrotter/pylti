import argparse
import base64
import hmac
import hashlib
import html
import json
import time
import urllib.parse
import uuid

o_sig = 'oauth_signature'
o_key = 'oauth_consumer_key'
o_ts = 'oauth_timestamp'
o_nonce = 'oauth_nonce'
lti_version = 'lti_version'
lti_message_type = 'lti_message_type'
launch_token_secret = 'token_secret'
launch_method = 'method'


def encode(value):
    return urllib.parse.quote(value, safe='')


def bash_encode(value):
    return '$\'' + value.translate(
        str.maketrans({
            "'": "\\'",
            "\t": "\\t",
            "\n": "\\n",
            "\r": "\\r"
        })
    ) + '\''


class LTI(object):
    def __init__(self, args):
        self.args = args
        self.parameters = None
        self.url = None
        self.secret = None
        self.token_secret = ''
        self.method = 'POST'
        self.sorted_keys = None

    def process(self):
        lti_input = json.load(self.args.file)

        self.parameters = lti_input['parameters']
        if lti_version not in self.parameters:
            self.parameters[lti_version] = 'LTI-1p0'
        if lti_message_type not in self.parameters:
            self.parameters[lti_message_type] = 'basic-lti-launch-request'
        if o_sig in self.parameters:
            del self.parameters[o_sig]
        self.parameters['oauth_version'] = '1.0'
        if o_nonce not in self.parameters:
            self.parameters[o_nonce] = str(uuid.uuid4())
        if o_ts not in self.parameters:
            self.parameters[o_ts] = str(int(time.time()))

        self.parameters['oauth_signature_method'] = 'HMAC-SHA1'

        if launch_method in lti_input:
            self.method = lti_input[launch_method]
        if launch_token_secret in lti_input:
            self.token_secret = lti_input[launch_token_secret]

        self.url = lti_input['url']

        sbs = '&'.join([
            self.method,
            encode(self.url),
            encode(
                '&'.join(
                    ['{}={}'.format(k, encode(self.parameters[k])) for k in sorted(self.parameters)]
                )
            )
        ]).encode('utf-8')

        secret = '&'.join([
            lti_input['secret'],
            self.token_secret
        ]).encode('utf-8')
        signature = hmac.new(secret, sbs, hashlib.sha1).digest()
        self.parameters[o_sig] = base64.b64encode(signature).decode('utf-8')

        # re-sort keys after signature set
        self.sorted_keys = sorted(self.parameters)


class HTML(LTI):
    def process(self):
        super().process()
        fields = []
        for k in self.sorted_keys:
            html_key = html.escape(k)
            html_val = html.escape(self.parameters[k])
            fields.append(
                '<div>{}<input type="text" name="{}" value="{}" /></div>'.format(html_key, html_key, html_val)
            )
        h = '\n'.join([
            '<!DOCTYPE>',
            '<html>',
            '<body>',
            '<form name="params" method="{}" target="launch" action="{}">'.format(self.method, html.escape(self.url)),
            '\n'.join(fields),
            '<div><input type="submit" value="Launch" /></div>',
            '</form>',
            '<iframe name="launch" ></iframe>',
            '</body>',
            '</html>'
        ])
        self.args.output.write(h)


class Curl(LTI):
    def process(self):
        super().process()
        print('{}_URL={}'.format(self.args.prefix, bash_encode(self.url)))
        print('{}_PARAMS={}'.format(
            self.args.prefix,
            bash_encode(' '.join(['-d {}={}'.format(k, v) for k, v in self.parameters.items()]))
        ))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True, type=argparse.FileType(mode='r', encoding='utf-8'))
    sub = parser.add_subparsers()

    html_parser = sub.add_parser('html')
    html_parser.add_argument('--output', required=True, type=argparse.FileType(mode='w', encoding='utf-8'))
    html_parser.set_defaults(impl=HTML.__name__)

    curl_parser = sub.add_parser('curl')
    curl_parser.add_argument('--prefix', required=False, default='LTI')
    curl_parser.set_defaults(impl=Curl.__name__)

    args = parser.parse_args()
    impl = globals()[args.impl](args)
    impl.process()


if __name__ == "__main__":
    main()

# response = urllib.request.urlopen(
#     urllib.request.Request(
#         url=url,
#         method=method,
#         data=urllib.parse.urlencode(parameters).encode('utf-8')
#     )
# )
# with response:
#     print(response.info())
