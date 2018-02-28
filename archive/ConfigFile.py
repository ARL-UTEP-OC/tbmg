import xml.etree.ElementTree as ETree
import ConfigParser
from os import getcwd
from os.path import join

    
def load(xmlFile):
    global config = parseXMLConfig(xmlFile)
    
    c = ConfigParser.SafeConfigParser()
    c.read(join(getcwd(), "models", config["modelName"], 'config.ini'))
    global versions = parseVersions(c)
    global paths = parsePaths(c)

def parseXMLConfig(filename):
    answer = []
    
    #Model Basis
    answer["protoName"] = None
    answer["pcapFilename"] = None
    answer["keyword"] = None
    answer["multi"] = None
    
    #Model Generation
    answer["modelName"] = None
    answer["netLayer"] = None
    answer["transLayer"] = None
    
    #Scenario Generation
    answer["remote"] = "10.0.0.1"
    answer["local"] = "10.0.0.22"
    answer["gateway"] = "0.0.0.0"
    answer["hil"] = False

    tree = ETree.parse(filename)
    root = tree.getroot()

    # ModelBasis
    modelBasis = root.find('model-basis')
    
    # ModelGeneration
    modelGeneration = root.find('model-generation')
    
    # Scenario Generation
    scenGeneration = root.find('scenario-generation')

    # Grab each ModelBasis value
    answer["protoName"] = modelBasis.find('proto-name').text.rstrip().lstrip()
    answer["pcapFilename"] = modelBasis.find('path-to-pcap').text.rstrip().lstrip()
    
    # Grab optional identifier
    keyword = modelBasis.find('keyword')
    if keyword is not None and keyword.text is not None:
        answer["keyword"] = keyword.text.rstrip().lstrip()
    multi = modelBasis.find('multi-inclusive')
    if multi is not None and multi.text is not None:
        answer["multi"] = multi.text.rstrip().lstrip()

    # Grab each ModelGeneration value
    answer["modelName"] = modelGeneration.find('model-name').text.rstrip().lstrip()

    netLayer = modelGeneration.find('network-layer')
    if netLayer is not None and netLayer.text is not None:
        answer["netLayer"] = netLayer.text.rstrip().lstrip()
    transLayer = modelGeneration.find('transport-layer')
    if transLayer is not None and transLayer.text is not None:
        answer["transLayer"] = transLayer.text.rstrip().lstrip()

    # Grab Scenario Generation information
    remote = scenGeneration.find('remote-ip')
    if remote is not None and remote.text is not None:
        answer["remote"] = remote.text.rstrip().lstrip()
    local = scenGeneration.find('local-ip')
    if local is not None and local.text is not None:
        answer["local"] = local.text.rstrip().lstrip()
    gateway = scenGeneration.find('gateway-ip')
    if gateway is not None and gateway.text is not None:
        answer["gateway"] = gateway.text.rstrip().lstrip()
    hil = scenGeneration.find('hil')
    if hil is not None and hil.text is not None:
        answer["hil"] = hil.text.rstrip().lstrip()
    
    return answer

def createVersions(f, c):
    c.add_section('versions')
    c.set('versions', 'ns3', '3.26')
    c.set('versions', 'scapy', '2.3.2')
    
    with open(f, 'w') as o:
        c.write(o)

def createPaths(self, f, c):
    base = getcwd()
    modelpath = join(base, self.modelName)
    
    types = ['ns3', 'scapy']
    
    c.add_section('paths')
    c.set('paths', 'exbar', join(base, 'exbar'))
    c.set('paths', 'prospex', join(base, 'prospex'))
    c.set('paths', 'ns3', join(base, 'ns-allinone-3.26','ns-3.26')) #' + str(self.versions['ns3']), 'ns-' + str(self.versions['ns3'])))
    c.set('paths', 'model', modelpath)
    c.set('paths', 'statemachine', join(modelpath, 'statemachine'))
    c.set('paths', 'scratch', join(base, 'ns-allinone-3.26','ns-3.26','scratch'))
    
    for t in types:
        c.set('paths', t + '-model', join(modelpath, t, 'model'))
        c.set('paths', t + '-grammar', join(modelpath, t, 'grammar'))
        c.set('paths', t + '-scenario', join(modelpath, t, 'scenario'))
        c.set('paths', t + '-captures', join(modelpath, t, 'results'))
    
    with open(f, 'w+') as o:
        c.write(o)

def parseVersions(c):
    return c.items('versions')
    
def parsePaths(c):
    return c.items('paths')
    
    
    
    
        
