import { computed, observer } from '@ember/object';

import $ from 'jquery';
import Component from '@ember/component';
import DataTablesHelpers from 'api-umbrella-admin-ui/utils/data-tables-helpers';
import clone from 'lodash-es/clone';
import compact from 'lodash-es/compact';
import escape from 'lodash-es/escape';
import extend from 'lodash-es/extend';
import tippy from 'tippy.js'

export default Component.extend({
  didInsertElement() {
    this.$().find('table').DataTable({
      searching: false,
      serverSide: true,
      ajax: {
        url: '/api-umbrella/v1/analytics/logs.json',
        // Use POST for this endpoint, since the URLs can be very long and
        // exceed URL length limits in IE (and apparently Capybara too).
        type: 'POST',
        data: function(data) {
          return extend({}, data, this.backendQueryParamValues);
        }.bind(this),
      },
      drawCallback: () => {
        this.$().find('td').each(function() {
          if(this.scrollWidth > this.offsetWidth) {
            const $cell = $(this);
            $cell.attr('data-tippy-content', $cell.text());

            tippy($cell[0], {
              interactive: true,
              theme: 'light-border forced-wide',
              arrow: true,
              delay: 200,
            });
          }
        });
      },
      order: [[0, 'desc']],
      columns: [
        {
          data: 'request_at',
          type: 'date',
          title: 'Time',
          defaultContent: '-',
          render: DataTablesHelpers.renderTime,
        },
        {
          data: 'request_method',
          title: 'Method',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_host',
          title: 'Host',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_url',
          title: 'URL',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'user_email',
          title: 'User',
          defaultContent: '-',
          render: function(email, type, data) {
            if(type === 'display' && email && email !== '-') {
              let params = clone(this.presentQueryParamValues);
              params.search = compact([params.search, 'user_id:"' + data.user_id + '"']).join(' AND ');
              let link = '#/stats/logs?' + $.param(params);

              return '<a href="' + link + '">' + escape(email) + '</a>';
            }

            return email;
          }.bind(this),
        },
        {
          data: 'request_ip',
          title: 'IP Address',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_ip_country',
          title: 'Country',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_ip_region',
          title: 'State',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_ip_city',
          title: 'City',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'response_status',
          title: 'Status',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'gatekeeper_denied_code',
          title: 'Reason Denied',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'response_time',
          title: 'Response Time',
          defaultContent: '-',
          render(time, type) {
            if(type === 'display' && time && time !== '-') {
              return time + ' ms';
            }

            return time;
          },
        },
        {
          data: 'response_content_type',
          title: 'Content Type',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_accept_encoding',
          title: 'Accept Encoding',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_user_agent',
          title: 'User Agent',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_user_agent_family',
          title: 'User Agent Family',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_user_agent_type',
          title: 'User Agent Type',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_referer',
          title: 'Referer',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
        {
          data: 'request_origin',
          title: 'Origin',
          defaultContent: '-',
          render: DataTablesHelpers.renderEscaped,
        },
      ],
    });
  },

  refreshData: observer('backendQueryParamValues', function() {
    this.$().find('table').DataTable().draw();
  }),

  downloadUrl: computed('backendQueryParamValues', function() {
    return '/api-umbrella/v1/analytics/logs.csv?' + $.param(this.backendQueryParamValues);
  }),
});
