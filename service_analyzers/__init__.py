''' 
    The commented out code dynamically adds all modules in this subdirectory 
    to be loaded in when you call:

    from service_analyzers import *

    However, implicit loading makes it hard to see what modules are loaded in,
    and also the IDE doesn't realize the modules have been loaded in, causing 
    wrong warnings. All of this could get confusing, so I recommend adding
    submodules directly, i.e.

    from service_analyzers import iam
    from service_analyzers import s3 
    etc...
'''

# import glob
# import os

# # Get file paths of all modules.

# a = os.path.dirname(__file__)
# subdirectory = os.path.basename(a)

# modules = glob.glob(subdirectory+'\*.py')

# for i in range(len(modules)):
#     modules[i] = os.path.basename(modules[i]).strip('.py')
    
# __all__ = [modules]
# print(__all__)
# # Dynamically load those modules here.