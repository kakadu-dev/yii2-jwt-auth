<?php
/**
 * Created by Yii2 Gii.
 * User: Yarmaliuk Mikhail
 * Date: 23.10.2018
 * Time: 13:46
 */

namespace MP\Yii2JwtAuth;

use Yii;
use yii\db\ActiveRecord;

/**
 * Class    ApiToken
 * @package MP\Yii2JwtAuth
 * @author  Yarmaliuk Mikhail
 * @version 1.0
 *
 * This is the model class for table "{{%api_auth_tokens}}".
 *
 * @property string $access_token
 * @property string $refresh_token
 * @property int    $user_id
 * @property int    $access_expires
 * @property int    $refresh_expires
 */
class ApiToken extends ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName(): string
    {
        return '{{%api_auth_tokens}}';
    }

    /**
     * @inheritdoc
     */
    public function rules(): array
    {
        return [
            [['access_token', 'refresh_token', 'user_id'], 'required'],
            [['user_id', 'access_expires', 'refresh_expires'], 'integer'],
            [['access_token', 'refresh_token'], 'string', 'max' => 255],
            [['refresh_token'], 'unique'],
            [['access_token', 'refresh_token'], 'unique'],
            [['access_expires', 'refresh_expires'], 'default', 'value' => 0, 'skipOnEmpty' => false],
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels(): array
    {
        return [
            'access_token'    => Yii::t('app', 'Access Token'),
            'refresh_token'   => Yii::t('app', 'Refresh Token'),
            'user_id'         => Yii::t('app', 'User ID'),
            'access_expires'  => Yii::t('app', 'Access Expires'),
            'refresh_expires' => Yii::t('app', 'Refresh Expires'),
        ];
    }

    /**
     * @inheritdoc
     * @return ApiTokenQuery the active query used by this AR class.
     */
    public static function find(): ApiTokenQuery
    {
        return new ApiTokenQuery(get_called_class());
    }
}
