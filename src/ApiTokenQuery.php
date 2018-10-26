<?php
/**
 * Created by Yii2 Gii.
 * User: Yarmaliuk Mikhail
 * Date: 23.10.2018
 * Time: 13:46
 */

namespace Kakadu\Yii2JwtAuth;

use yii\db\ActiveQuery;
use yii\db\BatchQueryResult;

/**
 * Class    ApiTokenQuery
 * @package Kakadu\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 *
 * This is the ActiveQuery class for [[ApiToken]].
 *
 * @see     ApiToken
 *
 * @method ApiToken[]|array all($db = null)
 * @method ApiToken|array|null one($db = null)
 * @method ApiToken[]|BatchQueryResult each($batchSize = 100, $db = null)
 */
class ApiTokenQuery extends ActiveQuery
{
}
