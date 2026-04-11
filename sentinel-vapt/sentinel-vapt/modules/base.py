class BaseModule:
    name = 'base'
    category = 'general'

    def run(self, context):
        raise NotImplementedError
