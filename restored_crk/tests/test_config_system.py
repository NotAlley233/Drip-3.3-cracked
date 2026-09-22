"""Offline integration checks; never write to a live game or live panel."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from panel_server import CATALOG, FIELDS, FORMATS, Controller, validate_values
from hotkeys import KeyEdges


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.control=Controller(True,self.temp.name)

    def tearDown(self):
        self.control.close()
        self.temp.cleanup()

    def change(self, action, **kwargs):
        return self.control.change(action,{'revision':self.control.revision,**kwargs})

    def test_all_fields_pack_without_overlap(self):
        occupied={}
        for key,f in FIELDS.items():
            for offset in range(f['offset'],f['offset']+struct.calcsize(FORMATS[f['type']])):
                self.assertNotIn(offset,occupied,(key,occupied.get(offset)))
                self.assertLess(offset,CATALOG['size'])
                occupied[offset]=key
            for v in [f['min'],f['max']]:
                values=validate_values({key:v})
                self.assertIn(key,values)

    def test_matching_baseline_modified_rollback(self):
        baseline=self.control.read_live()
        self.assertEqual(struct.unpack_from('<f',baseline,0x5c)[0],25)
        self.change('patch',values={'auto-clicker.cps':30})
        changed=self.control.read_live()
        self.assertEqual([i for i,(a,b) in enumerate(zip(baseline,changed)) if a!=b],[0x5e])
        self.change('undo')
        self.assertEqual(self.control.read_live(),baseline)

    def test_invalid_import_is_atomic(self):
        self.change('patch',values={'auto-clicker.cps':30})
        before=self.control.snapshot()
        for values in [{'auto-clicker.cps':40,'unknown':1},{'auto-clicker.cps':float('nan')}, {'velocity.mode':2}, {'auto-clicker.key':3.2}, {'auto-clicker.cps':True}, {'auto-clicker.enabled':2}, {'backtrack.min-range':8,'backtrack.max-range':2}]:
            with self.assertRaises(ValueError):self.change('import',values=values)
            after=self.control.snapshot()
            self.assertEqual(before['revision'],after['revision'])
            self.assertEqual(before['overrides'],after['overrides'])

    def test_pair_rejects_crossing_existing_endpoint(self):
        self.change('patch',values={'backtrack.min-range':2,'backtrack.max-range':4})
        with self.assertRaises(ValueError):self.change('patch',values={'backtrack.min-range':5})
        self.assertEqual(self.control.overrides['backtrack.min-range'],2)

    def test_stale_revision_rejected(self):
        self.change('patch',values={'auto-clicker.cps':30})
        with self.assertRaises(ValueError):
            self.control.change('reset',{'revision':0})
        self.assertEqual(self.control.overrides,{'auto-clicker.cps':30})

    def test_pause_reset_and_undo(self):
        self.change('patch',values={'auto-clicker.cps':30,'backtrack.delay':200})
        paused=self.change('active',enabled=False)
        self.assertEqual(paused['values']['auto-clicker.cps'],25)
        self.change('active',enabled=True)
        reset=self.change('reset',module='backtrack')
        self.assertEqual(reset['overrides'],{'auto-clicker.cps':30})
        self.assertEqual(self.change('undo')['overrides']['backtrack.delay'],200)

    def test_named_profiles_and_restart(self):
        self.change('patch',values={'auto-clicker.cps':36,'velocity.require-click':1})
        self.change('active',enabled=False)
        self.change('profile-save',name='中文配置')
        self.change('reset')
        loaded=self.change('profile-load',name='中文配置')
        self.assertEqual(loaded['overrides']['auto-clicker.cps'],36)
        self.assertFalse(loaded['enabled'])
        self.control.close()
        self.control=Controller(True,self.temp.name)
        self.assertEqual(self.control.overrides['auto-clicker.cps'],36)
        self.assertFalse(self.control.enabled)
        self.assertIn('中文配置',self.control.store.list())
        self.change('profile-delete',name='中文配置')
        self.assertEqual(self.control.store.list(),[])

    def test_profile_path_cannot_escape_store(self):
        for name in ['../outside','..','foo/bar','foo\\bar','a:b','a'*49,'']:
            with self.assertRaises(ValueError):self.change('profile-save',name=name)

    def test_corrupt_autosave_preserved_and_reported(self):
        path=self.control.data/'autosave.json'
        path.write_text('{broken')
        self.control.close()
        self.control=Controller(True,self.temp.name)
        self.assertIsNotNone(self.control.persistence_error)
        self.assertEqual(path.read_text(),'{broken')

    def test_save_failure_exposed(self):
        with patch('panel_server.atomic_json',side_effect=OSError('disk full')):
            state=self.change('patch',values={'auto-clicker.cps':30})
        self.assertEqual(state['values']['auto-clicker.cps'],30)
        self.assertIn('disk full',state['persistence_error'])

    def test_closed_controller_rejects_mutations(self):
        self.control.close()
        with self.assertRaises(RuntimeError):self.change('patch',values={'auto-clicker.cps':30})

    def test_rebind_disables_native_key_and_pins_state(self):
        self.change('patch',values={'lag-range.key':66})
        self.assertEqual(self.control.overrides['lag-range.key'],66)
        self.assertEqual(self.control.overrides['lag-range.enabled'],0)
        self.assertEqual(self.control.snapshot()['values']['lag-range.key'],0)
        # Simulate loader old G key changing its source enabled state.
        source=bytearray(self.control.source)
        source[FIELDS['lag-range.enabled']['offset']]=1
        self.control.source=bytes(source)
        self.assertEqual(self.control.snapshot()['values']['lag-range.enabled'],0)
        self.change('patch',values={'lag-range.enabled':1})
        self.assertEqual(self.control.snapshot()['values']['lag-range.enabled'],1)

    def test_key_edges_focus_hold_release_rebind(self):
        edges=KeyEdges();bindings={'lag-range':66}
        self.assertEqual(edges.update(bindings,set(),True),[])
        self.assertEqual(edges.update(bindings,{71},True),[]) # old G ignored
        self.assertEqual(edges.update(bindings,{66},True),['lag-range'])
        self.assertEqual(edges.update(bindings,{66},True),[]) # no repeat while held
        self.assertEqual(edges.update(bindings,set(),True),[])
        self.assertEqual(edges.update(bindings,{66},True),['lag-range'])
        self.assertEqual(edges.update(bindings,set(),False),[])
        self.assertEqual(edges.update(bindings,{66},False),[]) # browser typing ignored
        self.assertEqual(edges.update(bindings,{66},True),[]) # held on focus ignored
        self.assertEqual(edges.update({'lag-range':74},{74},True),[]) # held at rebind ignored


if __name__=='__main__':unittest.main(verbosity=2)
