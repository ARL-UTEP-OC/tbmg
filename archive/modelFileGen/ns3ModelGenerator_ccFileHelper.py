#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

def generateFile(filename):
	ccFile = Template('''
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "{{jinjaModelName}}-helper.h"
#include "ns3/{{jinjaModelName}}.h"
#include "ns3/names.h"

namespace ns3 {

{{jinjaModelName}}Helper::{{jinjaModelName}}Helper (Ipv4Address remote)
{
  m_factory.SetTypeId ("ns3::{{jinjaModelName}}");
  m_factory.Set ("Remote", Ipv4AddressValue (remote));
}

void
{{jinjaModelName}}Helper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
{{jinjaModelName}}Helper::Install (Ptr<Node> node) const
{
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
{{jinjaModelName}}Helper::Install (std::string nodeName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
{{jinjaModelName}}Helper::Install (NodeContainer c) const
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }

  return apps;
}

Ptr<Application>
{{jinjaModelName}}Helper::InstallPriv (Ptr<Node> node) const
{
  Ptr<{{jinjaModelName}}> app = m_factory.Create<{{jinjaModelName}}> ();
  node->AddApplication (app);

  return app;
}

} // namespace ns3
''')
	ofile = open(filename, 'w')
	ofile.write(ccFile.render(jinjaModelName=modelName))
	#print ccFile.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFields, todo='TODO')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	outputPath = modelName+"/"+modelName+"model/"
	generateFile(outputPath+modelName+"-helper.cc")
if __name__ == "__main__":
	main()
