/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { QueryDslQueryContainer, SearchRequest } from '@elastic/elasticsearch/lib/api/types';
import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { ALERT_RISK_SCORE } from '@kbn/rule-registry-plugin/common/technical_rule_data_field_names';
import { withSecuritySpan } from '../../utils/with_security_span';
import type {
  CalculateRiskScoreAggregations,
  FullRiskScore,
  GetScoresParams,
  GetScoresResponse,
  IdentifierType,
  RiskScoreBucket,
  RiskScoreWeight,
  SimpleRiskScore,
  WatchList,
  WatchListMap,
} from './types';

const getFieldForIdentifierAgg = (identifierType: IdentifierType): string =>
  identifierType === 'host' ? 'host.name' : 'user.name';

const bucketToResponse = ({
  bucket,
  enrichInputs,
  now,
  identifierField,
}: {
  bucket: RiskScoreBucket;
  enrichInputs?: boolean;
  now: string;
  identifierField: string;
}): SimpleRiskScore | FullRiskScore => ({
  '@timestamp': now,
  identifierField,
  identifierValue: bucket.key[identifierField],
  calculatedLevel: bucket.risk_details.value.level,
  calculatedScore: bucket.risk_details.value.score,
  calculatedScoreNorm: bucket.risk_details.value.normalized_score,
  notes: bucket.risk_details.value.notes,
  riskiestInputs: enrichInputs
    ? bucket.riskiest_inputs.hits.hits
    : bucket.riskiest_inputs.hits.hits.map((riskInput) => ({
        _id: riskInput._id,
        _index: riskInput._index,
        sort: riskInput.sort,
      })),
});

const filterFromRange = (range: GetScoresParams['range']): QueryDslQueryContainer => ({
  range: { '@timestamp': { lt: range.end, gte: range.start } },
});

const isGlobalWeight = (weight: RiskScoreWeight): boolean => weight.type === 'global';

const getGlobalIdentifierWeight = ({
  identifierType,
  weights,
}: {
  identifierType: IdentifierType;
  weights: GetScoresParams['weights'];
}): number | undefined => {
  return weights?.find((weight) => isGlobalWeight(weight))?.[identifierType];
};

const getUpdatedRisk = (risk: number, multiplier: number) => {
  const odds = risk / (100 - risk);
  const newOds = odds * multiplier;

  return (100 * newOds) / (1 + newOds);
};

const applyWatchListScores = (
  scores: SimpleRiskScore[] | FullRiskScore[],
  watchListsMap: Record<string, string>
) => {
  return scores.map((item) => {
    const watchListScore = watchListsMap[item.identifierValue];
    // eslint-disable-next-line prefer-const
    let { calculatedScoreNorm, calculatedLevel, notes, ...rest } = item;

    if (watchListScore) {
      let multiplier = 1;
      switch (watchListScore) {
        case 'Critical':
          multiplier = 2;
          break;
        case 'Medium':
          multiplier = 0.5;
          break;
        case 'Low':
          multiplier = 0.25;
          break;
        default:
          break;
      }

      const updatedScoreNorm = getUpdatedRisk(calculatedScoreNorm, multiplier);
      const update = updatedScoreNorm - calculatedScoreNorm;
      notes.push(
        `Asset criticality modifier: ${update > 0 ? '+' : '-'}${Math.abs(update).toFixed(4)}`
      );
      calculatedScoreNorm = updatedScoreNorm;
    }

    if (calculatedScoreNorm < 20) {
      calculatedLevel = 'Unknown';
    } else if (calculatedScoreNorm >= 20 && calculatedScoreNorm < 40) {
      calculatedLevel = 'Low';
    } else if (calculatedScoreNorm >= 40 && calculatedScoreNorm < 70) {
      calculatedLevel = 'Moderate';
    } else if (calculatedScoreNorm >= 70 && calculatedScoreNorm < 90) {
      calculatedLevel = 'High';
    } else if (calculatedScoreNorm >= 90) {
      calculatedLevel = 'Critical';
    }

    return {
      calculatedScoreNorm,
      calculatedLevel,
      notes,
      ...rest,
    };
  });
};

const buildReduceScript = ({
  globalIdentifierWeight,
}: {
  globalIdentifierWeight?: number;
}): string => {
  return `
    Map results = new HashMap();
    List scores = [];
    for (state in states) {
      scores.addAll(state.scores)
    }
    Collections.sort(scores, Collections.reverseOrder());

    double num_inputs_to_score = Math.min(scores.length, params.max_risk_inputs_per_identity);
    results['notes'] = [];
    if (num_inputs_to_score == params.max_risk_inputs_per_identity) {
      results['notes'].add('Number of risk inputs (' + scores.length + ') exceeded the maximum allowed (' + params.max_risk_inputs_per_identity + ').');
    }

    double total_score = 0;
    for (int i = 0; i < num_inputs_to_score; i++) {
      total_score += scores[i] / Math.pow(i + 1, params.p);
    }

    ${globalIdentifierWeight != null ? `total_score *= ${globalIdentifierWeight};` : ''}
    double score_norm = 100 * total_score / params.risk_cap;
    results['score'] = total_score;
    results['normalized_score'] = score_norm;

    if (score_norm < 20) {
      results['level'] = 'Unknown'
    }
    else if (score_norm >= 20 && score_norm < 40) {
      results['level'] = 'Low'
    }
    else if (score_norm >= 40 && score_norm < 70) {
      results['level'] = 'Moderate'
    }
    else if (score_norm >= 70 && score_norm < 90) {
      results['level'] = 'High'
    }
    else if (score_norm >= 90) {
      results['level'] = 'Critical'
    }

    return results;
  `;
};

const buildIdentifierTypeAggregation = (
  identifierType: IdentifierType,
  enrichInputs?: boolean,
  weights?: GetScoresParams['weights']
): SearchRequest['aggs'] => {
  const globalIdentifierWeight = getGlobalIdentifierWeight({ identifierType, weights });
  const identifierField = getFieldForIdentifierAgg(identifierType);

  return {
    [identifierType]: {
      // per identity field, per category
      composite: {
        size: 65536, // TODO make a param,
        sources: [
          {
            [identifierField]: {
              terms: {
                field: identifierField,
              },
            },
          },
        ],
        after: undefined, // TODO make a param
      },
      aggs: {
        riskiest_inputs: {
          // TODO top_metrics would be faster if enrichInputs is false
          top_hits: {
            size: 30,
            sort: [
              {
                [ALERT_RISK_SCORE]: {
                  order: 'desc',
                },
              },
            ],
            _source: enrichInputs,
          },
        },
        risk_details: {
          scripted_metric: {
            init_script: 'state.scores = []',
            map_script: `state.scores.add(doc['${ALERT_RISK_SCORE}'].value)`,
            combine_script: 'return state',
            params: {
              max_risk_inputs_per_identity: 999999,
              p: 1.5,
              risk_cap: 261.2,
            },
            reduce_script: buildReduceScript({ globalIdentifierWeight }),
          },
        },
      },
    },
  };
};

export const calculateRiskScores = async ({
  debug,
  enrichInputs,
  esClient,
  filter: userFilter,
  identifierType,
  index,
  logger,
  range,
  weights,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
} & GetScoresParams): Promise<GetScoresResponse> =>
  withSecuritySpan('calculateRiskScores', async () => {
    const now = new Date().toISOString();

    const filter = [{ exists: { field: ALERT_RISK_SCORE } }, filterFromRange(range)];
    if (userFilter) {
      filter.push(userFilter as QueryDslQueryContainer);
    }
    const identifierTypes: IdentifierType[] = identifierType ? [identifierType] : ['host', 'user'];

    const request = {
      size: 0,
      _source: false,
      index,
      query: {
        bool: {
          filter,
        },
      },
      aggs: identifierTypes.reduce(
        (aggs, _identifierType) => ({
          ...aggs,
          ...buildIdentifierTypeAggregation(_identifierType, enrichInputs, weights),
        }),
        {}
      ),
    };

    if (debug) {
      logger.info(`Executing Risk Score query:\n${JSON.stringify(request)}`);
    }

    const response = await esClient.search<never, CalculateRiskScoreAggregations>(request);

    if (debug) {
      logger.info(`Received Risk Score response:\n${JSON.stringify(response)}`);
    }

    if (response.aggregations == null) {
      return { ...(debug ? { request, response } : {}), scores: [] };
    }

    const userBuckets = response.aggregations.user?.buckets ?? [];
    const hostBuckets = response.aggregations.host?.buckets ?? [];

    const watchListReponse = await esClient.search<never, WatchList[]>({
      size: 9000,
      index: 'watch-list*',
    });

    const wathcListMap = watchListReponse?.hits?.hits
      ?.map((item) => item._source as unknown as WatchList)
      ?.reduce(
        (acc, val) => {
          if (val.identifierField === 'host.name') {
            acc.host[val.identifierValue] = val.riskLevel;
          } else if (val.identifierField === 'user.name') {
            acc.user[val.identifierValue] = val.riskLevel;
          }
          return acc;
        },
        { user: {}, host: {} } as WatchListMap
      );


    const userResponse = applyWatchListScores(
      userBuckets.map((bucket) =>
        bucketToResponse({
          bucket,
          enrichInputs,
          identifierField: 'user.name',
          now,
        })
      ),
      wathcListMap.user
    );

    const hostResponse = applyWatchListScores(
      hostBuckets.map((bucket) =>
        bucketToResponse({
          bucket,
          enrichInputs,
          identifierField: 'host.name',
          now,
        })
      ),
      wathcListMap.host
    );

    const scores = userResponse.concat(hostResponse);

    return {
      ...(debug ? { request, response } : {}),
      scores,
    };
  });
