import os
import sys
sys.path.insert(0, os.path.abspath('../..'))  # points to repo root

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Smart Meeting Room & Management System'
copyright = '2025, Ahmad Hlayhel & Boulos Boulos'
author = 'Ahmad Hlayhel & Boulos Boulos'
release = '1.0.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",   # for our Google/Numpy style docstrings
    "sphinx.ext.viewcode",   # link to source code
    "sphinx.ext.autosummary",
]
autosummary_generate = True


templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
