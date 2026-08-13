from __future__ import annotations

import unittest
from unittest.mock import patch

from src import effect_simulation
from src.effect_simulation import MagicSchoolID, magic_school_index
from wizwalker.memory.memory_objects.enums import MagicSchool


class EffectSimulationSchoolTests(unittest.TestCase):
    def test_numeric_school_ids_map_to_their_stat_indexes(self):
        self.assertEqual(magic_school_index(MagicSchool.fire.value), 0)
        self.assertEqual(magic_school_index(MagicSchool.balance.value), 6)

    def test_school_names_and_enum_members_remain_supported(self):
        self.assertEqual(magic_school_index("shadow"), 11)
        self.assertEqual(magic_school_index(MagicSchool.cantrips), 13)

    def test_universal_school_identifier_compares_as_an_integer(self):
        self.assertEqual(MagicSchoolID.universal, 80289)

    def test_incoming_damage_uses_the_school_id_not_the_damage_amount(self):
        target = {"health": 500.0, "is_player": False}

        def cache_value(_cache, path):
            if path.endswith("_all"):
                return 0.0
            return [0.0] * len(effect_simulation.MagicSchoolIndex)

        with patch.object(
            effect_simulation,
            "cache_get",
            side_effect=cache_value,
        ), patch.object(
            effect_simulation,
            "sim_incoming_dmg_effects",
            side_effect=lambda target, school, damage, pierce: (
                target,
                school,
                damage,
                pierce,
            ),
        ):
            result, damage = effect_simulation.sim_incoming_damage(
                {},
                target,
                MagicSchool.fire.value,
                100.0,
            )

        self.assertEqual(damage, 100.0)
        self.assertEqual(result["health"], 400.0)


if __name__ == "__main__":
    unittest.main()
