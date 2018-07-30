import interceptor
from scapy.all import *
from lxml import objectify,etree
from Tkinter import *
import tkFileDialog
sys.path.insert(0, '../scapyProxy')
from GuiUtils import VerticalScrolledFrame


class AbstractHook(object):
    def __init__(self, scapy_packet_, description_=None):
        self.scapy_packet = scapy_packet_
        self.description = description_
        self._is_active = False
        #self._hook_dir = None
        #self._hook_file = None
        #self._hookframe = None
        #self._class_name = None
        self.ACCEPT = interceptor.NF_ACCEPT
        self.DROP = interceptor.NF_DROP
        
    def run(self):
        pass
    
    def _initFrame(self):
        self._hookframe
    
    
class FilterHook(AbstractHook):
    def __init__(self, scapy_packet_, description_=None):
        AbstractHook.__init__(self, scapy_packet_, description_)
        self.interfaces = []
    
    def catch(self):
        return True
    
    def ignore(self):
        return False
    
    def run(self):
        pass


class PacketHook(AbstractHook):
    def __init__(self, scapy_packet_, description_=None):
        AbstractHook.__init__(self, scapy_packet_, description_)
        self.filter_bnf = ''
        self.filter_hook =['','']
    
    def accept(self):
        return self.scapy_packet, self.ACCEPT
    
    def drop(self):
        return self.scapy_packet, self.DROP
    
    def run(self):
        pass
    

#TODO might want to  move to different file due to imports and that this file is used by other users
class HookProfile(object):
    def __init__(self, profile_path=None, tbmg=None):
        self.tbmg = tbmg
        print 'hookprofile tmbg:',self.tbmg
        self.hook_manager = []#=[[(class)class, (string - dir path)module, (string)file, (class)super, (string)description, (bool)active],[],....]
        self.xml_root = None
        self.profile_path = profile_path if profile_path else 'active.xml'
        if os.path.isfile(self.profile_path):
            self.loadFromXML()
        else:
            self.saveTo(self.profile_path)
    
    #serialize self from xml
    def loadFromXML(self, new_profile_path=None):
        self.hook_manager = []
        try:
            if new_profile_path:
                self.profile_path=new_profile_path
            xml = open(self.profile_path, 'r').read()
            print 'loading from xml:',self.profile_path
            blank_packet = IP()
            self.xml_root = objectify.fromstring(xml)
            for h in self.xml_root.getchildren():
                print 'hook xml:',str(etree.tostring(h,pretty_print=True))
                sys.path.append(str(h.module))
                print 'added to path:', h.module
                try:
                    module = __import__(str(h.file))
                except:
                    print 'could not import module:', h.file,type(str(h.file))
                    continue
                try:
                    class_ = getattr(module, str(h.class_name))
                    try:
                        class_(blank_packet)
                        # TODO check if isinstance of Hook (or parent(s) are)
                    except:
                        print 'could not instanciate class:', h.class_name
                        continue
                except:
                    print 'could not find class:', h.class_name
                    continue
                #TODO handle super
                self.hook_manager.append([class_, str(h.module), str(h.file), FilterHook, str(h.description), bool(h.active)])
                print 'added hook from xml:', class_, h.module, h.file, FilterHook, h.description, h.active
            
        except Exception as e:
            print 'Could not load from xml. Error: ',e
        self.tbmg.updateHookGUI()
    
    #serialize self to xml
    def _genXML(self):
        self.xml_root = objectify.Element('profile')
        for hook in self.hook_manager:
            h = objectify.SubElement(self.xml_root,'hook')
            h.super = "PacketHook" #TODO handle filter hook
            h.class_name = hook[0].__name__
            h.module = hook[1].strip()
            h.file = hook[2].strip()
            h.super = hook[3].__name__
            h.description = str(hook[4]).strip()
            h.active = hook[5]
        print 'genXML done:', str(etree.tostring(self.xml_root,pretty_print=True))
        self.tbmg.updateHookGUI()
        #update gui?
        return str(etree.tostring(self.xml_root,pretty_print=True))
    
    def saveTo(self,new_profile_path=None):
        if not new_profile_path:
            new_profile_path = self.profile_path
        else:
            new_profile_path = new_profile_path.name
        xml = self._genXML()
        if xml:
            print 'writing to',new_profile_path
            print 'writing:',xml
            f = open(new_profile_path, 'w')
            f.write(xml)
            f.close()
            
    def delHook(self, index):
        del (self.hook_manager[index])
        self.saveTo()
        self.tbmg.updateHookGUI()
            
    def addHook(self, hook_class, module_path, file_name, hook_super, description, active):
        if hook_super==None:
            hook_super = PacketHook #TODO handle fliter hook
        self.hook_manager.append([hook_class, module_path, file_name, hook_super, description, active])
        #self._genXML() #change to saveto?
        self.saveTo()
        
    def chooseHook(self):
        def find_between(s, first, last):
            # https://stackoverflow.com/questions/3368969/find-string-between-two-substrings
            try:
                start = s.index(first) + len(first)
                end = s.index(last, start)
                return s[start:end]
            except ValueError:
                return ""
    
        def selectClassInPyFile(file_path): #e.g. '/root/hook_file.py'
            classes = []
            hook_class = None
            module_path = None#
            file_name = None#
            description = None
            active = None
            with open(file_path, 'r') as f:
                class_names = []
                for line in f.readlines():
                    if 'class' in line and '(' in line and ')' in line and ':' in line:
                        class_name = find_between(line, 'class', '(').strip()
                        if class_name:
                            class_names.append(class_name)
                if class_names:
                    blank_packet = IP()
                    module_path = file_path[:file_path.rfind('/')]
                    sys.path.append(module_path)
                    print 'added to path:', file_path[:file_path.rfind('/')]
                    try:
                        file_name = file_path[file_path.rfind('/') + 1:file_path.rfind('.py')]
                        module = __import__(file_name)
                    except:
                        print 'could not import module:', file_name
                    for class_name in class_names:
                        try:
                            class_ = getattr(module, class_name)
                            try:
                                class_(blank_packet)
                                # TODO check if isinstance of Hook (or parent(s) are)
                                classes.append(class_)
                            except:
                                print 'could not instanciate class:', class_name
                        except:
                            print 'could not find class:', class_name
            if classes:
                if len(classes) == 1:
                    if classes[0]:
                        temp_instance = classes[0](None)  # TODO handle super
                        self.addHook(classes[0], module_path, file_name, PacketHook, temp_instance.description, False)
                        print 'SELECTED: ', classes[0].__name__
                    else:
                        print 'no hook selected'
                    return
            
                def setClass(class_):
                    print 'setClass:', class_
                    popup.destroy()
                    if class_:
                        temp_instance = class_(None)  # TODO handle super
                        self.addHook(class_, module_path, file_name, PacketHook, temp_instance.description, False)
                        print 'SELECTED: ', class_.__name__
                    else:
                        print 'no hook selected'
                    return
            
                popup = Toplevel()
                popup.title = 'Select Hook Class'
                scroll_classes = VerticalScrolledFrame(popup)
                scroll_classes.pack()
                for c in classes:
                    b = Button(scroll_classes.interior, text=c.__name__, command=lambda class_=c: setClass(class_),
                               width=40)
                    b.pack()
                print 'Waiting for class choosing'
            else:
                print 'Found no valid classes'
    
        name = tkFileDialog.askopenfilename(initialdir="/root/tbmg/bin/Hooks", filetypes=[("python", "*.py")])
        if not name:
            return
        path = name[:name.rfind('/')]
        if path != '/root/tbmg/bin/Hooks':
            pass  # copy?
        selectClassInPyFile(name)