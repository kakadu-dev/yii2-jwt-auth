<?php
/**
 * Created by Yii2 Gii.
 * User: Yarmaliuk Mikhail
 * Date: 23.10.2018
 * Time: 13:46
 */

namespace MP\Yii2JwtAuth;

use yii\db\ActiveQuery;
use yii\db\BatchQueryResult;

/**
 * Class    ApiTokenQuery
 * @package MP\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 *
 * This is the ActiveQuery class for [[ApiToken]].
 *
 * @see     ApiToken
 */
class ApiTokenQuery extends ActiveQuery
{
    /**
     * @inheritdoc
     * @return ApiToken[]|array
     */
    public function all($db = null)
    {
        return parent::all($db);
    }

    /**
     * @inheritdoc
     * @return ApiToken|array|NULL
     */
    public function one($db = null)
    {
        return parent::one($db);
    }

    /**
     * @inheritdoc
     * @return ApiToken[]|BatchQueryResult
     */
    public function each($batchSize = 100, $db = null)
    {
        return parent::each($batchSize, $db);
    }
}
