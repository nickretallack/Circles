from sqlalchemy import *
from sqlalchemy.orm import *
def association(cls, backref_name):
    """create an association 'interface'."""

    table = cls.__table__
    interface_name = table.name
    attr_name = "%s_rel" % interface_name

    metadata = table.metadata
    association_table = Table("%s_associations" % interface_name, metadata,
        Column('id', Integer, primary_key=True),
        Column('type', String(50), nullable=False)
    )

    class GenericAssoc(object):
        def __init__(self, name):
            self.type = name

    def interface(cls, name, uselist=True):

        mapper = class_mapper(cls)
        table = mapper.local_table
        mapper.add_property(attr_name, 
                            relationship(GenericAssoc, 
                                    backref=backref('_backref_%s' % table.name, uselist=False))
                            )

        if uselist:
            # list based property decorator
            def get(self):
                if getattr(self, attr_name) is None:
                    setattr(self, attr_name, GenericAssoc(table.name))
                return getattr(self, attr_name).targets
            setattr(cls, name, property(get))
        else:
            # scalar based property decorator
            def get(self):
                return getattr(self, attr_name).targets[0]
            def set(self, value):
                if getattr(self, attr_name) is None:
                    setattr(self, attr_name, GenericAssoc(table.name))
                getattr(self, attr_name).targets = [value]
            setattr(cls, name, property(get, set))

    @property
    def items(self):
        return getattr(self.association, '_backref_%s' % self.association.type)

    setattr(cls, backref_name, items)

    mapper(GenericAssoc, association_table, properties={
        'targets':relationship(cls, backref='association'),
    })

    return interface
