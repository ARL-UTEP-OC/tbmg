from os import stat
from os.path import exists, isdir
from distutils.dir_util import copy_tree, mkpath
from distutils.file_util import copy_file



def creationCheck(filename):
    assert stat(filename).st_size > 0 and exists(filename) == True, "Error: " + filename + " is missing/empty. Aborting."
    #try:
        #assert stat(filename).st_size > 0 and exists(filename) == True
    #except AssertionError:
        #print "Error: " + filename + " is missing/empty. Aborting."
        
def copy(src, dest):
    creationCheck(src)
    if isdir(src):
        c = copy_tree(src, dest)
    else:
        try:
            c = copy_file(src, dest)
        except IOError:
            mkpath(src[:src.rindex('/')])
            c = copy_file(src, dest)
    assert len(c) > 0, "Error copying " + src + " to " + dest

