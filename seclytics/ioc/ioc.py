from datetime import datetime


class Ioc(object):

    def __init__(self, client, intel):
        self.client = client
        self.time_fmt = u"%Y-%m-%dT%H:%M:%S"
        self.intel = intel

    @property
    def reported_by(self):
        '''Which data source categorized this IOC
        This could be a feed or another provider of threat intelligence.
        '''
        reported_by = []
        if 'context' not in self.intel:
            return reported_by
        reported_by = self.intel[u'context'][u'categories'].keys()
        return reported_by

    @property
    def has_threat_intel(self):
        '''Returns True if we have intel or False if there is none'''
        return len(self.reported_by) > 0

    def _namespaced_values(self, kind):
        '''Extract all the namespaced values (internal use)
        To keep track of what source said what each field in the context is
        namespaced by the source who reported it.
        '''
        values = []
        if 'context' not in self.intel:
            return values
        context = self.intel[u'context']
        if kind in context:
            values = set([v
                         for src, value in context[kind].items()
                         for v in value])
        return list(values)

    @property
    def categories(self):
        '''All the categories associated with this IOC'''
        return self._namespaced_values(u'categories')

    @property
    def identifiers(self):
        '''All the identifiers associated with this IOC
        This could be the name of the threat actor, tool or exploit type'''
        return self._namespaced_values(u'identifiers')

    @property
    def reasons(self):
        '''Additional data associated with categorization'''
        return self._namespaced_values(u'reasons')

    @property
    def source_urls(self):
        '''These are URLs you can get more detailed info on this IOC'''
        return self._namespaced_values(u'source_urls')

    @property
    def passive_dns(self):
        '''Passive DNS data for this IOC'''
        if u'passive_dns' in self.intel:
            return self.intel[u'passive_dns']

    @property
    def predictions(self):
        '''Predictions that apply to this IOC'''
        if u'predictions' in self.intel:
            return self.intel[u'predictions']

    @property
    def predicted(self):
        '''Simple check to see if IOC is predicted

        Returns:
            bool: True if predicted, False otherwise.
        '''
        predictions = self.predictions
        return predictions is not None and len(predictions) > 0

    @property
    def predicted_at(self):
        '''The current predicted_at'''
        if u'prediction' not in self.intel:
            return None
        prediction = self.intel[u'prediction']
        return datetime.strptime(prediction[u'predicted_at'], self.time_fmt)

    
    @property
    def first_reported_at(self):
        '''The first time this IOC has been seen by our threat intel'''

        if u'history' not in self.intel:
            return None 
        history = self.intel[u'history']
        if u'first_seen_at' not in history:
            return None
        return datetime.strptime(history[u'first_seen_at'], self.time_fmt)

    @property
    def ioc_type(self):
        '''The kind of IOC represented in the report
        This could be IP, CIDR, ASN, Host or File'''
        return self.intel[u'type']

    @property
    def ioc_id(self):
        '''The IOC'''
        return self.intel[u'id']

    @property
    def whitelist(self):
        '''Returns the whitelist message'''
        if u'whitelist' in self.intel:
            return self.intel[u'whitelist']
    
    @property
    def rankings(self):
        if u'rankings' in self.intel:
            return self.intel[u'rankings']

    def min_ranking(self, allowed_lists=None):
        rankings = self.rankings
        if rankings is None:
            return None
        
        min_ranking = None
        for list_name, value in rankings.items():
            if allowed_lists and list_name not in allowed_lists:
                continue
            list_min = value.get(u'min', None)
            if list_min and (min_ranking is None or int(list_min) < min_ranking):
                min_ranking = int(list_min)

        return min_ranking
        
    
    def record_threat_data(self, category=None, reason=None, feed=None):
        data = {'classification': 'malicious'}
        if category:
            data['category'] = category
        if reason:
            data['reason'] = reason
        if feed:
            data['feed'] = feed
        path = '/%ss/%s' % (self.ioc_type, self.ioc_id)
        return self.client._post_data(path, data)

    def mark_as_good(self, reason=None, feed=None):
        data = {'classification': 'benign'}
        if reason:
            data['reason'] = reason
        if feed:
            data['feed'] = feed
        path = '/%ss/%s' % (self.ioc_type, self.ioc_id)
        return self.client._post_data(path, data)
