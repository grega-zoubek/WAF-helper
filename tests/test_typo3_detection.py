import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'services/discovery-worker'))
from app.technology_detection import detect_technology_signals
class Typo3Tests(unittest.TestCase):
 def test_exact_generator(self):
  rows=detect_technology_signals(url='https://site.test',meta={'generator':'TYPO3 CMS'})
  typo=next(x for x in rows if x['technology']=='TYPO3 CMS')
  self.assertEqual(typo['technology_key'],'typo3-cms')
  self.assertIsNone(typo.get('version'))
 def test_plain_text_does_not_establish_product(self):
  rows=detect_technology_signals(url='https://site.test',body='We work with TYPO3 CMS')
  self.assertFalse(any(x['technology']=='TYPO3 CMS' for x in rows))
