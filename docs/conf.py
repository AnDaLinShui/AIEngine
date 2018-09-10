import sys, os

sys.path.insert(0, os.path.abspath('extensions'))

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.doctest', 'sphinx.ext.todo',
              'sphinx.ext.coverage', 'sphinx.ext.ifconfig']

todo_include_todos = True
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'aiengine'
exclude_patterns = []
add_function_parentheses = True

project = u'AIEngine'
copyright = u'2018, Luis Campo Giralte'
author = u'Luis Campo Giralte'

version = '1.9'
release = '1.9'

pygments_style = 'sphinx'
html_static_path = ['_static']

