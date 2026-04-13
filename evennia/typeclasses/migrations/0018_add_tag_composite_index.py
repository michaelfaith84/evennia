# Generated 2026-04-13
#
# Migration 0017 used a get_operations() instance method that Django never calls —
# Django reads only the `operations` class attribute, which was [] — so 0017 was a
# no-op for all databases.  The composite index on typeclasses_tag was therefore
# never created.  This migration creates it directly.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("typeclasses", "0017_use_index_instead_of_index_together_in_tags"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="tag",
            index=models.Index(
                fields=["db_key", "db_category", "db_tagtype", "db_model"],
                name="typeclasses_db_key_be0c81_idx",
            ),
        ),
    ]
