from flask import Flask, redirect, request, Response, jsonify, render_template
from urllib import urlencode
import re
from functools import wraps
import requests
import json
import cgi
import copy
from config import AUTH_BASE, API_BASE, CLIENT_SECRET, CLIENT_ID, REDIRECT_URI

# we use this to shorten a long resource reference when displaying it
MAX_LINK_LEN = 20
# we only care about genomic stuff here
REF_RE = re.compile(r'^(?:Condition|Patient|Sequence|Procedure|Observation)/.*$')
# list of scopes we need
# list of scopes we need
SCOPES = ['user/Sequence.read',
        'user/Observation.read',
        'user/Condition.read',
        'user/Patient.read',
        'user/Procedure.read',
        'user/MedicationPrescription.read']
        
CYP2C19_SNP_STAR_TRANSLATION = {
  'rs4244285' : { 'normal': 'G', 'star': '*2' },
  'rs4986893' : { 'normal': 'G', 'star': '*3' },
  'rs28399504' : { 'normal': 'A', 'star': '*4' },
  'rs56337013' : { 'normal': 'C', 'star': '*5' },
  'rs72552267' : { 'normal': 'G', 'star': '*6' },
  'rs72558186' : { 'normal': 'T', 'star': '*7' },
  'rs41291556' : { 'normal': 'T', 'star': '*8' },
  'rs12248560' : { 'normal': 'C', 'star': '*17' }
}

CYP2C19_LOOKUP = {
  '*1/*1': {'text': 'Extensive Metabolizer', 'display_class': 'normal'},
  '*1/*2': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*3': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*4': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*5': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*6': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*7': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*8': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*1/*17': {'text': 'Ultrarapid Metabolizer', 'display_class': 'normal'},
  '*2/*17': {'text': 'Intermediate Metabolizer', 'display_class': 'warn'},
  '*17/*17': {'text': 'Ultrarapid Metabolizer', 'display_class': 'normal'},
  '*2/*2': {'text': 'Poor Metabolizer', 'display_class': 'alert'},
  '*2/*3': {'text': 'Poor Metabolizer', 'display_class': 'alert'},
  '*3/*3': {'text': 'Poor Metabolizer', 'display_class': 'alert'}
}

CYP2C19_DETAILS = {
  'Extensive Metabolizer': ['If your doctor ever prescribes you the drug clopidogrel, you should be able to process it normally.', 'You should be able to process your clopidogrel normally.'],
  'Ultrarapid Metabolizer': ['If your doctor ever prescribes you the drug clopidogrel, you should be able to process it normally.', 'You should be able to process your clopidogrel normally.'],
  'Intermediate Metabolizer': ['If your doctor ever prescribes you the drug clopidogrel, there is a chance you may be at a risk for an adverse cardiovascular event.  You should share these results with your care team.', 'People with your genotype are at a slight risk for an adverse cardiovascular event while taking clopidogrel.  You should share these results with your care team, and see if your physician may want to switch you to another medication.'],
  'Poor Metabolizer': ['If your doctor ever prescribes you the drug clopidogrel, you are at risk for an adverse cardiovascular event.  You should share these results with your care team.', 'People with your genotype are at risk for an adverse cardiovascular event while taking clopidogrel.  You should share these results with your care team, and see if your physician may want to switch you to another medication.']
}


app = Flask(__name__)

class OAuthError(Exception):
    pass

def get_access_token(auth_code):
    '''
    exchange `code` with `access token`
    '''
    exchange_data = {
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code'
    }
    resp = requests.post(AUTH_BASE+'/token', data=exchange_data)
    if resp.status_code != 200:
        raise OAuthError
    else:
        return resp.json()['access_token']

def api_call(api_endpoint):
    '''
    helper function that makes API call 
    '''
    access_token = request.cookies['access_token']
    auth_header = {'Authorization': 'Bearer %s'% access_token}
    return requests.get('%s%s'% (API_BASE, api_endpoint), headers=auth_header)

def to_internal_id(full_id):
    '''
    markup an internal resource id with anchor tag.
    e.g. change Patient/123 into <a href='...'>Patient/123</a>
    '''
    if not full_id.startswith(API_BASE):
        internal_id = full_id
    else:
        internal_id = full_id[len(API_BASE)+1:]

    return '<a href="/%s">%s...</a>'% (internal_id, internal_id[:MAX_LINK_LEN])

def has_access():
    '''
    check if application has access to API
    '''
    if 'access_token' not in request.cookies:
        return False
    # we are being lazy here and don't keep a status of our access token,
    # so we just make a simple API call to see if it expires yet
    test_call = api_call('/Patient?_count=1') 
    return test_call.status_code != 403


def render_fhir(resource):
    '''
    render a "nice" view of a FHIR bundle
    '''
    for entry in resource['entry']:
        entry['id'] = to_internal_id(entry.get('id', ''))

    return render_template('bundle_view.html', **resource)


def make_links(resource):
    '''
    scans a resource and replace internal resource references with anchor tags pointing to them
    e.g. turn {'reference': 'Patient/123'} into {'reference': '<a href="...">"Patient/123"</a>'}

    we are not reusing `def to_internal_id` here because that function shortens an id for styles
    '''
    for k, v in resource.iteritems():
        if isinstance(v, dict):
            make_links(v)
        elif isinstance(v, list):
            vs = v
            for v in vs:
                if isinstance(v, dict):
                    make_links(v)
        elif isinstance(v, basestring) and REF_RE.match(v) is not None:
            resource[k] = "<a href='/%s'>%s</a>"% (v, v)


def get_code_snippet(resource):
    code = copy.deepcopy(resource)
    if code.get('text', {}).get('div'):
        embeded_html = code['text']['div']
        code['text']['div'] = cgi.escape(embeded_html).encode('ascii', 'xmlcharrefreplace')
    # replace internal references with anchor tags
    make_links(code)
    return json.dumps(code, indent=4)



def require_oauth(view):
    @wraps(view)
    def authorized_view(*args, **kwargs):
        # check is we have access to the api, if not, we redirect to the API's auth page
        if has_access():
            return view(*args, **kwargs)
        else:
            redirect_args = {
                'scope': ' '.join(SCOPES),
                'client_id': CLIENT_ID,
                'redirect_uri': REDIRECT_URI,
                'response_type': 'code'}
            return redirect('%s/authorize?%s'% (AUTH_BASE, urlencode(redirect_args)))
    
    return authorized_view

def translate_snp_to_star_variant(lookup_table, snps, default):
    star_variants = [default, default]
    has_relevant_snps = False
    for snp in snps:
        values = snp['content']['read']
        snp_info = lookup_table.get(snp['content']['snp'])
        if not snp_info:
            continue

        has_relevant_snps = True
        # Homozygote
        if snp_info['normal'] != values[0] and snp_info['normal'] != values[1]:
            star_variants = [snp_info['star'], snp_info['star']]
        # Heterozygote
        elif snp_info['normal'] != values[0] or snp_info['normal'] != values[1]:
            # If this is the second homozygote result, move over the first default value
            if star_variants[1] != default:
                star_variants[0] = star_variants[1]
            star_variants[1] = snp_info['star']
            
    if not has_relevant_snps:
        return None
    else:
        return star_variants
    
    
def translate_genotype_to_phenotype(lookup_table, genotype, default):
    genotype_info = lookup_table.get(genotype)
    if not genotype_info:
        genotype_info = lookup_table[default]

    return genotype_info
    
def get_details(lookup_table, phenotype, is_on_med):
    result = lookup_table.get(phenotype)
    if not result:
      return ''
    
    return lookup_table[phenotype][(1 if is_on_med else 0)]

@app.route('/')
@require_oauth
def index():
    return forward_api('Patient')

@app.route('/Patient/<path:patient_id>')
@require_oauth
def patient(patient_id):
    if (not patient_id):
        return forward_api('Patient')

    print 'Displaying patient: ' + patient_id
    meds = get_fhir_bundle('MedicationPrescription', {'patient': patient_id})
    seq = get_fhir_bundle('Sequence', {'patient': patient_id})
    patient = get_fhir_bundle('Patient/' + patient_id, {})

    cyp2c19 = get_fhir_bundle('Observation', {'subject:Patient': patient_id, 'name': '124020'})
    phenotypes = []
    cyp2c19_phenotype = None
    if cyp2c19['totalResults'] < 1:
      print '** Need to look up sequences for CYP2C19'
      cyp2c19_star = translate_snp_to_star_variant(CYP2C19_SNP_STAR_TRANSLATION, seq['entry'], '*1')
      if not cyp2c19_star is None:
          cyp2c19_phenotype = translate_genotype_to_phenotype(CYP2C19_LOOKUP, '/'.join(cyp2c19_star), {'text': 'Intermediate Metabolizer', 'display_class': 'warn'})
          phenotypes.append({'text': 'You are predicted to be a(n) ' + cyp2c19_phenotype['text'] + ' of the drug clopidogrel', 'display_class': cyp2c19_phenotype['display_class']})
    else:
      cyp2c19_phenotype = translate_genotype_to_phenotype(CYP2C19_LOOKUP, cyp2c19['entry'][0]['content']['valueString'], {'text': 'Intermediate Metabolizer', 'display_class': 'warn'})
      phenotypes.append({'text': 'You are predicted to be a(n) ' + cyp2c19_phenotype['text'] + ' of the drug clopidogrel', 'display_class': cyp2c19_phenotype['display_class']})

    if cyp2c19_phenotype:
      found_med = next((med for med in meds['entry'] if med['content']['medication']['reference'] == 'Medication/clopidogrel'), None)
      phenotypes[0]['details'] = get_details(CYP2C19_DETAILS, cyp2c19_phenotype['text'], not (found_med is None))

    return render_template('genomics_view.html', patient= patient['entry'], medications= meds['entry'], observations= cyp2c19['entry'], sequences= seq['entry'], phenotypes= phenotypes)
        
    

@app.route('/recv_redirect')
def recv_code():
    code = request.args['code']
    access_token = get_access_token(code)
    resp = redirect('/')
    resp.set_cookie('access_token', access_token)
    return resp

def get_fhir_bundle(forwarded_url, forward_args):
    #forward_args = request.args.to_dict(flat=False)
    forward_args['_format'] = 'json'
    api_url = '/%s?%s'% (forwarded_url, urlencode(forward_args, doseq=True))
    api_resp = api_call(api_url)
    bundle = api_resp.json()
    # not bundle but plain resource
    if bundle['resourceType'] != 'Bundle':
        resource = bundle
        bundle = {
            'resourceType': resource['resourceType'],
            'entry': [{
                'content': resource,
                'id': forwarded_url
            }],
            'is_single_resource': True,
            'code_snippet': get_code_snippet(resource) 
        }
    elif len(bundle.get('entry', [])) > 0:
        bundle['resourceType'] = bundle['entry'][0]['content']['resourceType']

    return bundle
    

def forward_api(forwarded_url):
    bundle = get_fhir_bundle(forwarded_url, request.args.to_dict(flat=False))
    return render_fhir(bundle)


if __name__ == '__main__':
    app.run(debug=True, port=8000)
