
import sys

file = str(sys.argv[1])

flowFile= open(file, "r")
l, r = file.split("/")
new = l+"/packetTypeSequences.txt"
outFile = open(new, "w+")

def stripAll(str):

    pos = str.find('#')
    if pos != None:
        str = str[:pos]

    str=str.rstrip('\n')+" "
    #print "in strip method: "+str+ "\n"
    return str


types = ["Type", "type", "Message Type", "message type", "Command", "command", "GET", "POST", "NOTIFY"]
allTypes = [] # holds all protocol types
typesFound = [] #holds one of each protocol type
foundType = False
left = ""
right = ""
w=""
for line in flowFile:
    if not line.strip():
        foundType = False
        continue
    if foundType == False:
        try:
            left, right = line.split(":", 1)
        #       print left+"\n"
            left=left.rstrip('\n')+" "
            if right != "":
                right=stripAll(right)
        except ValueError:
            left = line
        if left == "unspecified ":
            #print "left was unspecified\n"
            #print "right: "+right
            blank, size, show, pos, value, name = line.split("#")
            left = show
            left=left.rstrip('\n')+" "
            #print "Left is not " + left
        for each in types:
            if each in left:
            #       print "found " + each + ": "+right
                if right != "":


                    allTypes.append(right)
                else:

                    allTypes.append(left)
                if right not in typesFound:
                    if right != "":

                        typesFound.append(right)
                    else:

                        typesFound.append(left)

                foundType = True
                break

if len(typesFound):
    for each in typesFound:
        print each
else:
    print "No Types Found"


for i in allTypes:
    #w+=i+" "
    ind = 0
    for x in typesFound:
        if x == i:
            outFile.write(str(ind)+" ")
            #print ind
            ind = 0
        ind += 1

    #outFile.write(typesFound.index(i))
#print typesFound.index(' 8 (Echo (ping) request)')
#print types.index('Type')
#print typesFound[0]
#print typesFound[1]
flowFile.close()
outFile.close()
